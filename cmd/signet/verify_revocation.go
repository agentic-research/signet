package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/revocation/cabundle"
	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/agentic-research/signet/pkg/signet"
)

// signet-5b1590: `signet verify` checks revocation against the authority's
// signed CA bundle. The checks themselves are pkg/revocation's
// CABundleChecker (signature over the canonical CBOR, freshness, seqno
// rollback, epoch, key id). This file only maps an X.509 chain onto the
// checker's inputs and adds what a certificate needs on top: the epoch must
// be present, it must not be ahead of the authority, and the bundle must
// carry an issue time.

// oidEpoch is the CA epoch at issuance, a DER INTEGER. Allocated by notme
// (worker/src/cert-authority.ts OID_EPOCH) and read by ley-line-open at the
// same number; signet does not write it.
var oidEpoch = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}

// caBundlePath is where a notme-style authority serves its signed bundle.
const caBundlePath = "/internal/ca-bundle"

const (
	// verifyMaxBundleAge is notme's own conformance bound for a bundle
	// (worker/src/revocation.ts BUNDLE_MAX_AGE_MS, five minutes). The
	// checker's shared default is an hour; for a CLI deciding whether a
	// cert is revoked, an hour-old bundle could hide an epoch bump.
	verifyMaxBundleAge = 300 * time.Second
	// verifyMaxFutureSkew bounds how far ahead of the local clock a
	// bundle's issuedAt may be (signet ADR-006 max_clock_skew).
	verifyMaxFutureSkew = 60 * time.Second
)

func checkRevocation(ctx context.Context, result *VerifyResult, opts verifyOptions) error {
	chain := result.chain
	if len(chain) < 2 {
		// A self-signed leaf in --ca: there is no issued cert to check.
		return errors.New("the verified chain has no certificate below the root; nothing carries an epoch to check")
	}
	leaf, root := chain[0], chain[len(chain)-1]

	authority, err := resolveRevocationAuthority(opts.authority, leaf)
	if err != nil {
		return err
	}
	storage, err := openSeqnoStorage(opts.stateDir)
	if err != nil {
		return err
	}

	// Rollback state, and the cache, are keyed by the pinned root, not by
	// the fetch URL. The URL may come from the leaf's wimse:// host, which a
	// holder of a revoked tier key chooses; keyed by URL, every new URL
	// would start a fresh seqno history and accept a replayed old bundle.
	stateID := anchorStateID(root)

	fetcher := cabundle.NewHTTPSFetcher(bundleURL(authority), noRedirectClient(opts.client))
	cache := cabundle.NewBundleCache(time.Minute)
	// The trust anchor is the --ca root the chain ended at. The bundle is
	// fetched over the network and is believed only once that key's
	// signature over it verifies.
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, root.PublicKey,
		revocation.WithMaxBundleAge(verifyMaxBundleAge),
		revocation.WithMaxFutureSkew(verifyMaxFutureSkew))

	// Fetch once through the shared cache so the bundle read here (for the
	// key id lookup and the report) is the one the checker verifies.
	bundle, err := cache.Get(ctx, stateID, fetcher)
	if err != nil {
		return fmt.Errorf("fetch CA bundle from %s: %w", bundleURL(authority), err)
	}
	kid := anchorKeyID(bundle, root)

	for _, c := range chain[:len(chain)-1] {
		epoch, err := certEpoch(c)
		if err != nil {
			return fmt.Errorf("certificate %q %w", c.Subject.CommonName, err)
		}
		token := &signet.Token{IssuerID: stateID, Epoch: epoch, KeyID: []byte(kid)}
		revoked, err := checker.IsRevoked(ctx, token)
		if err != nil {
			return explainBundleError(authority, storage.Path(stateID), err)
		}
		if revoked {
			if epoch < bundle.Epoch {
				return fmt.Errorf("certificate %q has epoch %d but the authority is at epoch %d: revoked",
					c.Subject.CommonName, epoch, bundle.Epoch)
			}
			return fmt.Errorf("the root key is not in the authority's bundle (bundle keyId %q): revoked by key rotation", bundle.KeyID)
		}
		// The checker refuses only an OLDER epoch. notme's own verifier is
		// strict: a cert from an epoch the authority has not reached is
		// forged or from another authority, and accepting it would let it
		// outrun every future revocation.
		if epoch > bundle.Epoch {
			return fmt.Errorf("certificate %q has epoch %d, ahead of the authority's epoch %d: refused",
				c.Subject.CommonName, epoch, bundle.Epoch)
		}
	}

	// The checker skips the age check for a bundle without issuedAt
	// (backward compatibility). Without it freshness is unknown, so refuse.
	// Checked after IsRevoked so a forged bundle reports its bad signature.
	if bundle.IssuedAt <= 0 {
		return errors.New("CA bundle carries no issuedAt, so its freshness cannot be checked")
	}

	result.Revocation = RevocationResult{
		Checked:   true,
		Authority: authority,
		Epoch:     bundle.Epoch,
		BundleAge: time.Since(time.Unix(bundle.IssuedAt, 0)),
	}
	return nil
}

// anchorStateID names the rollback history of the authority whose root is
// root: the SHA-256 of the root's SubjectPublicKeyInfo. It is fixed by the
// --ca pin, so it cannot be changed by choosing a different fetch URL.
func anchorStateID(root *x509.Certificate) string {
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	return "root-spki-sha256:" + hex.EncodeToString(sum[:])
}

// errBundleRedirect is returned for any redirect from the bundle endpoint.
var errBundleRedirect = errors.New("the CA bundle endpoint redirected; redirects are refused")

// noRedirectClient returns a copy of base (or a default client) that
// refuses every redirect. The https-or-loopback rule is applied to the URL
// signet requests; following a redirect would let an allowed endpoint hand
// the fetch to plain http elsewhere. notme's bundle endpoint answers 200
// directly, so refusing costs nothing.
func noRedirectClient(base *http.Client) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if base != nil {
		cp := *base
		c = &cp
	}
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%w (to %s)", errBundleRedirect, req.URL.Redacted())
	}
	return c
}

// explainBundleError adds what the operator can do about the two refusals
// that have a recovery path.
func explainBundleError(authority, statePath string, err error) error {
	switch {
	case errors.Is(err, revocation.ErrBundleRollback):
		return fmt.Errorf("CA bundle from %s: %w. The last seqno seen is stored in %s; deleting that file is only safe if the authority's seqno was legitimately reset -- otherwise this is a replayed old bundle", authority, err, statePath)
	case errors.Is(err, revocation.ErrInvalidBundle):
		return fmt.Errorf("CA bundle from %s: %w. The authority's root may have rotated: re-fetch the root and re-pin --ca from a trusted channel, not from this authority's response alone", authority, err)
	default:
		return fmt.Errorf("CA bundle from %s: %w", authority, err)
	}
}

// resolveRevocationAuthority picks the authority whose bundle is consulted:
// the --authority flag, else https://auth.<trust domain> from the leaf's
// wimse:// URI (wimse://notme.bot/... -> https://auth.notme.bot). The URI is
// read from a cert whose chain has already verified, and the bundle it leads
// to is believed only if the pinned root signed it, so a wrong URL can cause
// a refusal but never an acceptance.
func resolveRevocationAuthority(flag string, leaf *x509.Certificate) (string, error) {
	raw := strings.TrimSpace(flag)
	if raw == "" {
		for _, u := range leaf.URIs {
			if u.Scheme == "wimse" && u.Host != "" {
				raw = "https://auth." + u.Host
				break
			}
		}
	}
	if raw == "" {
		return "", errors.New("no authority to check revocation against: the certificate has no wimse:// URI. Pass --authority URL, or --offline to skip the check")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid authority URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("authority URL %q must use https (plain http is allowed only for loopback)", raw)
		}
	default:
		return "", fmt.Errorf("authority URL %q must use https", raw)
	}
	// Accept either the base URL or the full bundle URL.
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), caBundlePath)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func bundleURL(authority string) string { return authority + caBundlePath }

// anchorKeyID returns the bundle key id whose key is the root's public key,
// or "" when the bundle does not list it. The checker refuses an empty key
// id (signet-676bf1), so a root missing from the bundle reads as revoked.
func anchorKeyID(bundle *types.CABundle, root *x509.Certificate) string {
	raw, err := algorithm.MarshalPublicKey(root.PublicKey)
	if err != nil {
		return ""
	}
	for kid, key := range bundle.Keys {
		if bytes.Equal(key, raw) {
			return kid
		}
	}
	return ""
}

// certEpoch reads the CA epoch extension. Go's encoding/asn1 enforces
// minimal DER, the same strictness notme's encoder was fixed to meet.
func certEpoch(c *x509.Certificate) (uint64, error) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidEpoch) {
			continue
		}
		var n *big.Int
		rest, err := asn1.Unmarshal(ext.Value, &n)
		if err != nil || len(rest) != 0 || n.Sign() < 0 || !n.IsUint64() {
			return 0, fmt.Errorf("has a malformed epoch extension (%s)", oidEpoch)
		}
		return n.Uint64(), nil
	}
	return 0, fmt.Errorf("has no epoch extension (%s): the authority does not publish revocation state for this certificate, so pass --offline if you accept that", oidEpoch)
}

// openSeqnoStorage opens the persisted last-seen bundle seqno, which is what
// makes rollback detectable across runs of a one-shot CLI. The files are
// HMAC-protected against casual edits; the key sits beside them, so this
// guards against a replayed old bundle, not against someone who can write
// the signet home directory.
func openSeqnoStorage(dir string) (*cabundle.FileStorage, error) {
	if dir == "" {
		return nil, errors.New("no state directory for the revocation seqno")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create revocation state dir: %w", err)
	}
	keyPath := filepath.Join(dir, "seqno-hmac.key")
	key, err := os.ReadFile(keyPath) // #nosec G304 - fixed name under the operator's signet home, not untrusted input
	if errors.Is(err, os.ErrNotExist) {
		key, err = createStateKey(keyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("revocation state key %s: %w", keyPath, err)
	}
	if len(key) != 32 {
		// Not self-healed. signet publishes the key only once it is
		// complete, so a short file was truncated or written by something
		// else; replacing it silently would also orphan every seqno file
		// HMAC'd under the old key.
		return nil, fmt.Errorf("revocation state key %s is corrupt (%d bytes, want 32). signet publishes this key only when complete, so it was truncated or written outside signet. To start over, delete %s; this discards the rollback history", keyPath, len(key), dir)
	}
	return cabundle.NewFileStorage(dir, key)
}

// createStateKey makes the HMAC key without ever exposing a partial one: the
// bytes go to a unique temp file that is fsynced and closed, then hard-linked
// to path. Link fails if path exists, so the first complete key wins, and a
// run that loses the race reads the winner's key -- which is complete,
// because it was published only after its bytes were on disk.
func createStateKey(path string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ReadFile(path) // #nosec G304 - as above; another run published its key first
		}
		return nil, err
	}
	return key, nil
}
