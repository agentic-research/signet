package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
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

	fetcher := cabundle.NewHTTPSFetcher(bundleURL(authority), opts.client)
	cache := cabundle.NewBundleCache(time.Minute)
	// The trust anchor is the --ca root the chain ended at. The bundle is
	// fetched over the network and is believed only once that key's
	// signature over it verifies.
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, root.PublicKey)

	// Fetch once through the shared cache so the bundle read here (for the
	// key id lookup and the report) is the one the checker verifies.
	bundle, err := cache.Get(ctx, authority, fetcher)
	if err != nil {
		return fmt.Errorf("fetch CA bundle from %s: %w", bundleURL(authority), err)
	}
	kid := anchorKeyID(bundle, root)

	for _, c := range chain[:len(chain)-1] {
		epoch, err := certEpoch(c)
		if err != nil {
			return fmt.Errorf("certificate %q %w", c.Subject.CommonName, err)
		}
		token := &signet.Token{IssuerID: authority, Epoch: epoch, KeyID: []byte(kid)}
		revoked, err := checker.IsRevoked(ctx, token)
		if err != nil {
			return fmt.Errorf("CA bundle from %s: %w", authority, err)
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
	return 0, fmt.Errorf("carries no epoch extension (%s), so it cannot be checked against revocation; use --offline to skip the check", oidEpoch)
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
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key, err = createStateKey(keyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("revocation state key %s: %w", keyPath, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("revocation state key %s is corrupt (%d bytes)", keyPath, len(key))
	}
	return cabundle.NewFileStorage(dir, key)
}

func createStateKey(path string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return os.ReadFile(path) // another run created it first
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	return key, f.Close()
}
