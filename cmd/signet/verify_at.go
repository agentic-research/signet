package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/rekor"
	"github.com/agentic-research/signet/pkg/revocation/epochhistory"
)

// signet-677e94: verify a certificate as of the time it signed.
//
// A release certificate lives five minutes, so by install time `signet
// verify` refuses it as expired and never reaches revocation. Verifying "as
// of the signing time" needs a signing time T nobody involved can choose:
// the Rekor integrated time of the signature, verified (pkg/rekor). The
// chain is then verified at T, and revocation is judged against the
// authority's SIGNED epoch history (pkg/revocation/epochhistory, notme
// ADR-019 D7): the certificate stands if its epoch was not revoked at or
// before T. The live CA bundle cannot answer that question; it only says
// which epoch is current now.
//
// T never comes from the local clock or from the signer. --at exists for an
// auditor who holds a timestamp signet cannot verify, and only together with
// --untrusted-time; the output then says the time is unverified.

// epochsPath is where a notme-style authority serves its signed history.
const epochsPath = "/.well-known/epochs.json"

// timeSource says where the verification time came from.
type timeSource int

const (
	timeNow       timeSource = iota // the local clock: revocation as of now only
	timeRekor                       // a verified Rekor integrated time
	timeUntrusted                   // --at with --untrusted-time
)

// verifyTime is the time the chain and revocation are judged at.
type verifyTime struct {
	source          timeSource
	at              time.Time
	logIndex        int64 // timeRekor
	artifactChecked bool  // timeRekor, with --artifact
}

// asOfSigning reports whether the check is as of a signing time.
func (v verifyTime) asOfSigning() bool { return v.source != timeNow }

// checkTimeFlags refuses combinations that would mislead.
func checkTimeFlags(opts verifyOptions) error {
	switch {
	case !opts.claimedAt.IsZero() && !opts.untrustedTime:
		return errors.New("--at takes the signing time from you, not from a trusted timestamp, so it needs --untrusted-time (the output then marks the time UNVERIFIED). For a verified time use --bundle <sigstore.json>")
	case opts.untrustedTime && opts.claimedAt.IsZero():
		return errors.New("--untrusted-time needs --at <RFC3339>")
	case opts.bundlePath != "" && !opts.claimedAt.IsZero():
		return errors.New("use --bundle or --at, not both: the bundle's Rekor time is the signing time")
	case opts.artifactPath != "" && opts.bundlePath == "":
		return errors.New("--artifact is checked against a bundle's Rekor entry; it needs --bundle")
	case opts.strictRevocation && opts.bundlePath == "" && opts.claimedAt.IsZero():
		return errors.New("--strict-revocation applies to a check as of a signing time (--bundle); a check as of now already refuses every revoked epoch")
	case opts.noArtifact && opts.bundlePath == "":
		return errors.New("--no-artifact applies only with --bundle")
	case opts.noArtifact && opts.artifactPath != "":
		return errors.New("use --artifact or --no-artifact, not both")
	case opts.bundlePath != "" && opts.artifactPath == "" && !opts.noArtifact:
		return errors.New("--bundle needs --artifact FILE, the file the bundle signs; without it nothing ties the result to the file you hold. Pass --no-artifact to verify only the certificate (the output then says artifact NOT checked, and signet exits 3)")
	case opts.historyMaxAge < 0:
		return errors.New("--history-max-age must not be negative")
	case opts.historyMaxAge != 0 && !opts.strictRevocation:
		return errors.New("--history-max-age applies only with --strict-revocation: a check that is not strict needs no fresh history")
	}
	return nil
}

// Exit codes of `signet verify`.
const (
	exitVerified         = 0 // valid, verified in full
	exitRefused          = 1 // invalid, or an error
	exitReducedAssurance = 3 // valid, but with reduced assurance
)

// defaultHistoryMaxAge bounds the epoch history's age in strict mode:
// notme's own bundle conformance bound (BUNDLE_MAX_AGE_MS), five minutes.
const defaultHistoryMaxAge = 300 * time.Second

// reducedAssuranceError is returned for a certificate that verified, but
// with a check skipped or a time nobody vouches for. It exits 3, so a script
// keyed on the exit code cannot mistake it for a full verification.
type reducedAssuranceError struct{ reasons []string }

func (e *reducedAssuranceError) Error() string {
	return "certificate valid with reduced assurance: " + strings.Join(e.reasons, "; ")
}

// ExitCode is the process exit status for this result.
func (e *reducedAssuranceError) ExitCode() int { return exitReducedAssurance }

// exitCodeOf maps verifyAndReport's result to the exit status.
func exitCodeOf(err error) int {
	var r *reducedAssuranceError
	switch {
	case err == nil:
		return exitVerified
	case errors.As(err, &r):
		return r.ExitCode()
	default:
		return exitRefused
	}
}

// reducedAssurance names what a valid result did not establish, or nil.
// --offline as of now keeps its exit 0 (the existing contract); as of a
// signing time it is reduced.
func reducedAssurance(vt verifyTime, opts verifyOptions) error {
	var reasons []string
	if vt.source == timeUntrusted {
		reasons = append(reasons, "the time is UNVERIFIED (--untrusted-time)")
	}
	if opts.noArtifact {
		reasons = append(reasons, "artifact NOT checked (--no-artifact)")
	}
	if opts.offline && vt.asOfSigning() {
		reasons = append(reasons, "revocation NOT checked (--offline)")
	}
	if len(reasons) == 0 {
		return nil
	}
	return &reducedAssuranceError{reasons: reasons}
}

// resolveSigningTime establishes T from --bundle (verified) or --at.
func resolveSigningTime(certPath string, opts verifyOptions) (verifyTime, error) {
	if opts.bundlePath == "" {
		return verifyTime{source: timeUntrusted, at: opts.claimedAt.UTC()}, nil
	}
	leaf, err := readLeafCert(certPath)
	if err != nil {
		return verifyTime{}, err
	}
	raw, err := readBounded(opts.bundlePath, rekor.MaxBundleSize)
	if err != nil {
		return verifyTime{}, fmt.Errorf("read bundle: %w", err)
	}
	ropts := rekor.Options{Logs: opts.rekorLogs}
	if opts.artifactPath != "" {
		f, err := os.Open(opts.artifactPath) // #nosec G304 - operator-supplied path to the artifact being verified
		if err != nil {
			return verifyTime{}, fmt.Errorf("open artifact: %w", err)
		}
		defer func() { _ = f.Close() }()
		ropts.Artifact = f
	}
	res, err := rekor.VerifyBundle(raw, leaf, ropts)
	if errors.Is(err, rekor.ErrNoTlogEntry) {
		return verifyTime{}, fmt.Errorf("%s: %w, so there is no trusted signing time: revocation can only be checked as of now (run without --bundle), and an expired certificate cannot be verified", opts.bundlePath, err)
	}
	if err != nil {
		return verifyTime{}, fmt.Errorf("%s: %w", opts.bundlePath, err)
	}
	return verifyTime{source: timeRekor, at: res.IntegratedTime, logIndex: res.LogIndex, artifactChecked: res.ArtifactChecked}, nil
}

// readLeafCert returns the first certificate in a PEM file.
func readLeafCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 - operator-supplied certificate path
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("failed to decode cert PEM")
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse cert: %w", err)
			}
			return c, nil
		}
	}
}

// readBounded reads at most limit bytes of a file, refusing a larger one.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 - operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// historyStateID names the rollback history of the authority's epoch
// history. It is keyed by the pinned root, like the CA bundle's (#198), but
// is a separate counter: notme signs the two documents with separate seqnos.
func historyStateID(root *x509.Certificate) string {
	return "epoch-history:" + anchorStateID(root)
}

// errHistoryRollback is a history whose seqno is below the last one seen.
var errHistoryRollback = errors.New("epoch history seqno decreased (rollback)")

// checkRevocationAt judges every certificate below the root against the
// authority's signed epoch history, as of T (ADR-019 D7):
//
//  1. the history's signature verifies under the --ca root the chain ended
//     at, and its seqno is not below the last one seen (gaps are normal);
//  2. T is before the history's issuedAt;
//  3. (the chain was verified at T by the caller);
//  4. each epoch is at most currentEpoch and was not revoked at or before T;
//     an ended epoch with no revocation record is refused;
//  5. --strict-revocation refuses any revoked epoch.
//
// Freshness is not required: a history that is old but issued after T still
// knows every revocation before T. A history dated more than the allowed
// skew into the future is refused all the same.
func checkRevocationAt(ctx context.Context, result *VerifyResult, opts verifyOptions, vt verifyTime) error {
	chain := result.chain
	if len(chain) < 2 {
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
	stateID := historyStateID(root)
	url := authority + epochsPath

	raw, err := fetchEpochHistory(ctx, opts.client, url)
	if err != nil {
		return err
	}
	h, err := epochhistory.Parse(raw)
	if errors.Is(err, epochhistory.ErrUnsigned) {
		return fmt.Errorf("the authority %s does not publish a signed epoch history yet (%s is the older, unsigned list, with no revocation times and nothing vouching for it), so revocation as of the signing time cannot be checked. Pass --offline to skip revocation; the output then says it was NOT checked", authority, url)
	}
	if err != nil {
		return fmt.Errorf("epoch history from %s: %w", url, err)
	}
	if err := epochhistory.VerifySignature(h, root.PublicKey); err != nil {
		return fmt.Errorf("epoch history from %s: %w. The authority's root may have rotated: re-fetch the root and re-pin --ca from a trusted channel", url, err)
	}
	now := opts.clock
	if now.IsZero() {
		now = time.Now()
	}
	issued := time.Unix(h.IssuedAt, 0).UTC()
	age := now.Sub(issued)
	if -age > verifyMaxFutureSkew {
		return fmt.Errorf("epoch history from %s is dated %s, more than %s in the future", url, issued.Format(time.RFC3339), verifyMaxFutureSkew)
	}
	// Strict refuses any revoked epoch, so it must see every revocation
	// made so far. A genuine but older history, issued after T and before a
	// revocation, would hide it, and a verifier with no rollback state (a new
	// machine, a CI runner) cannot tell. So strict needs a fresh history.
	// Non-strict does not: any history issued after T must already carry a
	// revocation at or before T.
	if opts.strictRevocation {
		maxAge := opts.historyMaxAge
		if maxAge == 0 {
			maxAge = defaultHistoryMaxAge
		}
		if age > maxAge {
			return fmt.Errorf("epoch history from %s is stale for --strict-revocation: issued %s, %s old, over the %s limit (--history-max-age). Strict mode refuses any revoked epoch, so it needs a history recent enough to carry every revocation; an older one could be replayed from before a revocation",
				url, issued.Format(time.RFC3339), age.Round(time.Second), maxAge)
		}
	}

	last, err := storage.GetLastSeenSeqno(ctx, stateID)
	if err != nil {
		return fmt.Errorf("epoch history rollback state: %w", err)
	}
	if h.Seqno < last {
		return fmt.Errorf("epoch history from %s: %w: seqno %d, last seen %d. The last seqno is stored in %s; deleting it is only safe if the authority's seqno was legitimately reset -- otherwise this is a replayed old history", url, errHistoryRollback, h.Seqno, last, storage.Path(stateID))
	}
	if err := storage.SetLastSeenSeqnoIfGreater(ctx, stateID, h.Seqno); err != nil {
		return fmt.Errorf("epoch history rollback state: %w", err)
	}

	var leafEpoch uint64
	for i, c := range chain[:len(chain)-1] {
		epoch, err := certEpoch(c)
		if err != nil {
			return fmt.Errorf("certificate %q %w", c.Subject.CommonName, err)
		}
		if i == 0 {
			leafEpoch = epoch
		}
		if err := epochhistory.StatusAt(h, epoch, vt.at.Unix(), opts.strictRevocation); err != nil {
			return fmt.Errorf("certificate %q: %w", c.Subject.CommonName, err)
		}
	}

	result.Revocation = RevocationResult{
		Checked:         true,
		AsOfSigning:     true,
		Authority:       authority,
		Epoch:           leafEpoch,
		CurrentEpoch:    h.CurrentEpoch,
		HistorySeqno:    h.Seqno,
		HistoryIssuedAt: issued,
		HistoryAge:      age,
		Strict:          opts.strictRevocation,
	}
	return nil
}

// fetchEpochHistory GETs the history: no redirects, bounded size.
func fetchEpochHistory(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := noRedirectClient(client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch epoch history from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch epoch history from %s: status %d", url, resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, epochhistory.MaxDocumentSize+1)); err != nil {
		return nil, fmt.Errorf("read epoch history from %s: %w", url, err)
	}
	if buf.Len() > epochhistory.MaxDocumentSize {
		return nil, fmt.Errorf("epoch history from %s is larger than %d bytes", url, epochhistory.MaxDocumentSize)
	}
	return buf.Bytes(), nil
}
