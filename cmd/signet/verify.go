package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/rekor"
	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/spf13/cobra"
)

var (
	verifyCAPath    string
	verifyAuthority string
	verifyOffline   bool
	// --legacy-cutoff is read through verifyLegacyCutoff, which needs to
	// know whether the flag was given at all; the variable is only its home.
	verifyLegacyCutoffFlag string

	// Verification as of the signing time (signet-677e94).
	verifyBundlePath       string
	verifyArtifactPath     string
	verifyAtFlag           string
	verifyUntrustedTime    bool
	verifyStrictRevocation bool
	verifyNoArtifact       bool
	verifyHistoryMaxAge    time.Duration
)

var verifyCmd = &cobra.Command{
	Use:   "verify <cert.pem>",
	Short: "Verify a bridge certificate against the signet CA, including revocation",
	Long: `Verify that a bridge certificate:
  1. Chains to the specified CA (or default signet CA)
  2. Is not expired
  3. Contains valid signet identity extensions
  4. Fits its notme criteria (.1.10), for a notme task certificate
  5. Has not been revoked: its CA epoch matches the authority's signed CA bundle

The cert file may hold the leaf followed by intermediates (for a notme task
certificate: task, then the tier). Intermediates only help build the path;
it must still end at a certificate in --ca.

Criteria. A notme task certificate names the criteria it was minted under
(OID 1.3.6.1.4.1.99999.1.10): agent-session/1 (at most 300s, scopes within
bridgeCert, sign:git, sign:attestation), llo-run/1 (300s, bridgeCert, and it
needs the run's confinementDigest, .1.7), or deploy/1 (900s, bridgeCert,
minted by the authority itself, never a tier). Its tier carries the
criteria its approver granted. These are notme's task-cert verify rules,
with its reasons. The certificate is refused when:
  - the tier carries criteria but the task names none;
  - the task names criteria the tier did not grant, or carries criteria
    under a tier that carries none;
  - its lifetime is over the criteria's limit;
  - a scope is outside the criteria's ceiling;
  - the criteria is minted elsewhere (a tier-signed deploy/1, a
    root-signed agent-session/1) or needs what the cert lacks;
  - the criteria is unknown or the extension is malformed.
A task with no criteria under a tier with none is legacy (pre-criteria). It
is accepted until the operator's cutoff, --legacy-cutoff ISO-DATE, or the
NOTME_LEGACY_CUTOFF environment variable (the flag wins). Certificates
that are not notme task certificates are not judged on criteria.

Revocation. After the chain verifies, signet fetches the authority's signed
CA bundle from <authority>/internal/ca-bundle and checks:
  - the bundle signature, against the --ca root the chain ended at (the
    pinned anchor; the network is not trusted);
  - freshness: the bundle's issuedAt must be at most 300s old (notme's own
    bound) and at most 60s in the future;
  - rollback: its seqno must not be lower than the last one seen (kept in
    <signet home>/revocation; delete it only if the authority's seqno was
    legitimately reset);
  - the root key is still in the bundle;
  - every certificate below the root carries a CA epoch (OID
    1.3.6.1.4.1.99999.1.4) equal to the bundle's epoch. An older epoch means
    the authority revoked it (for notme: POST /admin/revoke-epoch).
Any failure, including an unreachable authority, makes the certificate
invalid.

Authority. By default the bundle comes from https://auth.<trust domain>,
where the trust domain is the host of the certificate's wimse:// URI
(wimse://notme.bot/... -> https://auth.notme.bot). That convention fits the
public notme authority. A self-hosted authority at another address fails
closed until you name it with --authority URL. The URL is not trusted
either way: the bundle counts only if the pinned --ca root signed it.

As of the signing time. A release certificate lives five minutes, so by the
time anyone installs the release it is expired, and the checks above refuse
it before reaching revocation. --bundle <artifact.sigstore.json> verifies it
as of the moment it signed instead:
  - the signing time T is the Rekor integrated time of the bundle's entry,
    verified: the log's signed entry timestamp, the inclusion proof and its
    signed checkpoint, under the public-good Rekor key signet pins (and only
    inside that key's validity window); the entry must name this
    certificate and carry the bundle's signature, which must verify under
    the certificate's key. --artifact FILE, the file the bundle signs, is
    required and checked against the logged digest; --no-artifact skips it
    and the header then says "artifact NOT checked";
  - the chain, and the criteria, are verified at T;
  - revocation is checked against the authority's SIGNED epoch history at
    <authority>/.well-known/epochs.json (notme ADR-019 D7): its signature
    verifies under the --ca root, its seqno must not go backwards (gaps are
    fine; kept beside the bundle's in <signet home>/revocation), it must be
    issued after T, and each certificate's epoch must not have been revoked
    at or before T. An epoch that ended with no revocation record is
    refused: the history cannot say when it ended. The history need not be
    fresh: any history issued after T must already carry a revocation at
    or before T (this relies on the authority including every revocation
    in every later history).
    --strict-revocation refuses any revoked epoch, even for a signature made
    before the revocation. It does need a fresh history, at most 300s old
    by default (--history-max-age): an older genuine history could predate
    a revocation and hide it.
An authority that serves only the older, unsigned epochs.json cannot be
checked this way; the command says so and fails (or pass --offline).
T never comes from your clock or from the signer. A bundle with no Rekor
entry has no trusted time: revocation can then only be checked as of now.
--at RFC3339 takes T from you instead, only with --untrusted-time, and the
output marks it UNVERIFIED.

Exit status:
  0  valid, verified in full
  1  invalid, or an error
  3  valid with reduced assurance: --untrusted-time, --no-artifact, or
     --offline together with --bundle. (--offline without --bundle keeps
     exit 0, as before; its output says revocation NOT checked.)

A certificate with no epoch extension (for example one from signet's own Go
authority) is refused: its authority does not publish revocation state for
it. --offline skips the revocation check. The output then says "revocation
NOT checked": the certificate may already be revoked.

Extracts and displays: subject, task, sponsor, issuer, validity, key type,
and the revocation result.`,
	Example: `  signet verify ~/.signet/mcp/rosary/cert.pem
  signet verify cert.pem --ca /etc/signet/ca.pem
  signet verify task/chain.pem --ca root.pem
  signet verify cert.pem --ca root.pem --authority https://auth.notme.bot
  signet verify cert.pem --ca root.pem --offline
  signet verify task/chain.pem --ca root.pem --legacy-cutoff 2026-12-01
  signet verify signet-linux-amd64.signet.crt.pem --ca ca-bundle.pem \
      --bundle signet-linux-amd64.sigstore.json --artifact signet-linux-amd64`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyCAPath, "ca", "", "CA certificate PEM file (default: ~/.signet/ca.pem)")
	verifyCmd.Flags().StringVar(&verifyAuthority, "authority", "", "Authority URL serving /internal/ca-bundle (and, with --bundle, /.well-known/epochs.json) for the revocation check (default: https://auth.<trust domain> from the cert's wimse:// URI)")
	verifyCmd.Flags().BoolVar(&verifyOffline, "offline", false, "Skip the revocation check (output says \"revocation NOT checked\")")
	verifyCmd.Flags().StringVar(&verifyBundlePath, "bundle", "", "Sigstore bundle (.sigstore.json): verify as of its verified Rekor integrated time, with revocation from the signed epoch history")
	verifyCmd.Flags().StringVar(&verifyArtifactPath, "artifact", "", "With --bundle: also check this artifact against the logged digest")
	verifyCmd.Flags().StringVar(&verifyAtFlag, "at", "", "Verify as of this RFC3339 time; needs --untrusted-time, and the output marks the time UNVERIFIED")
	verifyCmd.Flags().BoolVar(&verifyUntrustedTime, "untrusted-time", false, "Accept --at, a time no trusted timestamp vouches for")
	verifyCmd.Flags().BoolVar(&verifyStrictRevocation, "strict-revocation", false, "With --bundle or --at: refuse any revoked epoch, even for a signature made before the revocation; needs a fresh epoch history (--history-max-age)")
	verifyCmd.Flags().BoolVar(&verifyNoArtifact, "no-artifact", false, "With --bundle: verify the certificate without the artifact (header says \"artifact NOT checked\", exit 3)")
	verifyCmd.Flags().DurationVar(&verifyHistoryMaxAge, "history-max-age", defaultHistoryMaxAge, "With --strict-revocation: the oldest epoch history accepted")
	verifyCmd.Flags().StringVar(&verifyLegacyCutoffFlag, "legacy-cutoff", "", "Refuse legacy (pre-criteria) notme task certs after this ISO date (default: $NOTME_LEGACY_CUTOFF; unset accepts them)")
	rootCmd.AddCommand(verifyCmd)
}

// VerifyResult holds the outcome of certificate verification.
type VerifyResult struct {
	Valid      bool
	Subject    string // CN
	Owner      string // OID 99999.1.1 (sponsor identity)
	Agent      string // OID 99999.1.5 (agent name, empty for human certs)
	Scope      string // OID 99999.1.6 (scope restriction, empty if unrestricted)
	Task       string // notme task id from OID 99999.1.9, empty unless a task cert
	Issuer     string // Issuer CN
	KeyType    string // "ECDSA P-256", "Ed25519", etc.
	NotBefore  time.Time
	NotAfter   time.Time
	Remaining  time.Duration
	Reason     string // if invalid, why
	Revocation RevocationResult
	Criteria   CriteriaResult
	// Time is what the chain and revocation were judged at (signet-677e94).
	Time verifyTime

	// noArtifact is --no-artifact: the header says the artifact was not checked.
	noArtifact bool

	// expired is set when the chain failed only because a certificate is
	// outside its validity window at the verification time.
	expired bool

	// chain is the verified path, leaf first and the --ca root last. Set
	// only when the chain verified; the revocation check reads it.
	chain []*x509.Certificate
}

// CriteriaResult records what the notme criteria (.1.10) check established.
type CriteriaResult struct {
	Checked bool   // the certificate is a notme task cert and was judged
	ID      string // the task's criteria, e.g. "agent-session/1"; empty if legacy
	Legacy  bool   // no criteria anywhere: issued under a pre-criteria tier
	ByTier  bool   // issued by a tier (else by the authority's root)
	Refused string // notme's reason, when refused
}

// RevocationResult records what the revocation check established.
type RevocationResult struct {
	Checked   bool          // the bundle (or history) was fetched, verified and every epoch passed
	Authority string        // where the bundle came from
	Epoch     uint64        // now: the authority's current epoch; as of signing: the leaf's epoch
	BundleAge time.Duration // age of the bundle at check time (as of now only)

	// As of the signing time (signet-677e94): judged against the signed
	// epoch history rather than the live bundle.
	AsOfSigning     bool
	CurrentEpoch    uint64 // the history's currentEpoch
	HistorySeqno    uint64
	HistoryIssuedAt time.Time
	HistoryAge      time.Duration // at check time
	Strict          bool
}

// verifyOptions carries everything a verification run needs, so tests can
// drive the same code path as the command.
type verifyOptions struct {
	caPath    string
	authority string       // --authority; empty means derive from the cert
	offline   bool         // --offline: skip the revocation check
	client    *http.Client // fetches the CA bundle
	stateDir  string       // holds the last-seen bundle seqno (rollback protection)

	// at is the verification time; zero means now. Tests pin it so golden
	// fixtures minted at a fixed time verify.
	at time.Time
	// legacyCutoff is --legacy-cutoff / NOTME_LEGACY_CUTOFF; nil means none.
	legacyCutoff *time.Time

	bundlePath       string
	artifactPath     string
	claimedAt        time.Time
	untrustedTime    bool
	strictRevocation bool
	noArtifact       bool          // --no-artifact: --bundle without checking the artifact
	historyMaxAge    time.Duration // --history-max-age (strict only); 0 means the default
	rekorLogs        []rekor.Log   // trusted logs; nil means the public-good Rekor
	// clock is "now" for the epoch history's age and skew; zero means
	// time.Now(). Tests pin it so fixture histories can be fresh.
	clock time.Time
}

func runVerify(cmd *cobra.Command, args []string) error {
	certPath := args[0]
	cfg := getConfig()

	if verifyCAPath == "" {
		// Try default location
		defaultCA := filepath.Join(cfg.Home, "ca.pem")
		if _, err := os.Stat(defaultCA); err == nil {
			verifyCAPath = defaultCA
		} else {
			return fmt.Errorf("no CA specified and no default at %s\n  Use: signet verify cert.pem --ca ca.pem\n  Or:  curl -s https://your-authority/.well-known/ca-bundle.pem > %s", defaultCA, defaultCA)
		}
	}

	legacyCutoff, err := verifyLegacyCutoff(cmd)
	if err != nil {
		return err
	}
	var historyMaxAge time.Duration
	if f := cmd.Flags().Lookup("history-max-age"); f != nil && f.Changed {
		historyMaxAge = verifyHistoryMaxAge
	}
	var claimedAt time.Time
	if verifyAtFlag != "" {
		claimedAt, err = time.Parse(time.RFC3339, verifyAtFlag)
		if err != nil {
			return fmt.Errorf("--at must be an RFC3339 time, such as 2026-10-28T23:39:48Z: %w", err)
		}
	}

	err = verifyAndReport(cmd.Context(), os.Stderr, certPath, verifyOptions{
		caPath:           verifyCAPath,
		authority:        verifyAuthority,
		offline:          verifyOffline,
		client:           &http.Client{Timeout: 15 * time.Second},
		stateDir:         filepath.Join(cfg.Home, "revocation"),
		legacyCutoff:     legacyCutoff,
		bundlePath:       verifyBundlePath,
		artifactPath:     verifyArtifactPath,
		claimedAt:        claimedAt,
		untrustedTime:    verifyUntrustedTime,
		strictRevocation: verifyStrictRevocation,
		noArtifact:       verifyNoArtifact,
		historyMaxAge:    historyMaxAge,
	})
	var reduced *reducedAssuranceError
	if errors.As(err, &reduced) {
		// Valid, at reduced assurance: not a usage error. Execute prints
		// the notice and exits 3.
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
	}
	return err
}

// verifyAndReport verifies the chain, then (unless offline) revocation, and
// writes the human-readable result to w. It returns an error whenever the
// certificate is not valid, so the exit status is non-zero.
func verifyAndReport(ctx context.Context, w io.Writer, certPath string, opts verifyOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := checkTimeFlags(opts); err != nil {
		return err
	}
	// The certificate file is read exactly once. The signing time, the
	// chain, the identity, the criteria and the epochs are all judged on
	// these bytes; reading the path twice would let a file swapped in
	// between supply the chain for another certificate's Rekor time.
	certPEM, err := os.ReadFile(certPath) // #nosec G304 - operator-supplied certificate path
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	if verifyAfterCertRead != nil {
		verifyAfterCertRead()
	}
	vt := verifyTime{source: timeNow, at: opts.at}
	if vt.at.IsZero() {
		vt.at = time.Now()
	}
	if opts.bundlePath != "" || opts.untrustedTime {
		leaf, _, err := parseCertPEM(certPEM)
		if err != nil {
			return err
		}
		if vt, err = resolveSigningTime(leaf, opts); err != nil {
			return err
		}
	}
	at := vt.at
	result, err := verifyCertPEM(certPEM, opts.caPath, at)
	if err != nil {
		return err
	}
	result.Time = vt

	// Criteria next, on a verified chain only (notme's verifyChain judges
	// criteria after the signatures), and before revocation: it is offline,
	// so a misfit is refused without asking the network anything.
	if result.Valid {
		checkTaskCriteria(result, at, opts.legacyCutoff)
	}

	// Revocation runs only on a chain that verified: the bundle is checked
	// against the root the chain ended at, and a cert that does not chain is
	// already invalid. Fail closed: any error here makes the cert invalid.
	if result.Valid && !opts.offline {
		check := checkRevocation
		if vt.asOfSigning() {
			check = func(ctx context.Context, r *VerifyResult, o verifyOptions) error {
				return checkRevocationAt(ctx, r, o, vt)
			}
		}
		if err := check(ctx, result, opts); err != nil {
			result.Valid = false
			result.Reason = "revocation check failed: " + err.Error()
		}
	}

	result.noArtifact = opts.noArtifact
	renderVerifyResult(w, result, opts.offline)

	if !result.Valid {
		return fmt.Errorf("certificate verification failed: %s", result.Reason)
	}
	return reducedAssurance(vt, opts)
}

func renderVerifyResult(w io.Writer, result *VerifyResult, offline bool) {
	// Output is best-effort (a terminal); a write error has nowhere to go.
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("\n")
	vt := result.Time
	asOf := ""
	switch vt.source {
	case timeRekor:
		asOf = " as of its signing time, " + vt.at.Format(time.RFC3339) + " (Rekor)"
	case timeUntrusted:
		asOf = " as of " + vt.at.Format(time.RFC3339) + ", an UNVERIFIED time (--untrusted-time)"
	}
	if result.noArtifact {
		asOf += " (artifact NOT checked)"
	}
	switch {
	case result.Valid && offline:
		p("%s Certificate valid%s (revocation NOT checked)\n", styles.Success.Render("✓"), asOf)
	case result.Valid:
		p("%s Certificate valid%s\n", styles.Success.Render("✓"), asOf)
	default:
		p("%s Certificate invalid: %s\n", styles.Error.Render("✗"), result.Reason)
	}
	switch vt.source {
	case timeRekor:
		p("  Signed at: %s (Rekor integrated time, log index %d, verified)\n", vt.at.Format(time.RFC3339), vt.logIndex)
		if vt.artifactChecked {
			p("  Artifact:  matches the logged digest\n")
		} else {
			p("  Artifact:  NOT checked (--no-artifact): this says nothing about any file you hold\n")
		}
	case timeUntrusted:
		p("  Time:      %s UNVERIFIED: supplied with --at, not a trusted timestamp; whoever chose it could have picked any time\n", vt.at.Format(time.RFC3339))
	}

	p("  Subject:   %s\n", styles.Code.Render(result.Subject))
	if result.Agent != "" {
		p("  Agent:     %s\n", styles.Code.Render(result.Agent))
	}
	if result.Scope != "" {
		p("  Scope:     %s\n", styles.Code.Render(result.Scope))
	}
	if result.Task != "" {
		p("  Task:      %s\n", styles.Code.Render(result.Task))
	}
	if result.Owner != "" {
		p("  Sponsor:   %s\n", styles.Code.Render(result.Owner))
	}
	p("  Issuer:    %s\n", styles.Code.Render(result.Issuer))
	p("  Key:       %s\n", styles.Code.Render(result.KeyType))
	p("  Valid:     %s → %s\n",
		result.NotBefore.Format(time.RFC3339),
		result.NotAfter.Format(time.RFC3339))
	if result.Valid && !vt.asOfSigning() {
		p("  Remaining: %s\n", result.Remaining.Round(time.Minute))
	}
	switch c := result.Criteria; {
	case c.Refused != "":
		p("  Criteria:  refused: %s\n", c.Refused)
	case c.Checked && c.Legacy:
		p("  Criteria:  none (legacy: issued under a pre-criteria tier)\n")
	case c.Checked && c.ByTier:
		p("  Criteria:  %s (within tier grant)\n", styles.Code.Render(c.ID))
	case c.Checked:
		p("  Criteria:  %s (authority-minted)\n", styles.Code.Render(c.ID))
	}
	switch r := result.Revocation; {
	case offline:
		p("  Revocation: revocation NOT checked (--offline): a revoked certificate still shows as valid\n")
	case r.Checked && r.AsOfSigning:
		strict := ""
		if r.Strict {
			strict = ", strict"
		}
		unverified := ""
		if vt.source == timeUntrusted {
			unverified = " (an UNVERIFIED time)"
		}
		p("  Revocation: checked as of the signing time%s: epoch %d not revoked at or before it (signed epoch history seqno %d, history issued %s, age %s, current epoch %d%s, %s)\n",
			unverified, r.Epoch, r.HistorySeqno, r.HistoryIssuedAt.UTC().Format(time.RFC3339), r.HistoryAge.Round(time.Second), r.CurrentEpoch, strict, r.Authority)
	case r.Checked:
		p("  Revocation: checked (epoch %d, bundle age %ds, %s), as of now\n",
			r.Epoch, int64(r.BundleAge.Seconds()), r.Authority)
	case result.expired && !vt.asOfSigning():
		p("  Revocation: not checked: the certificate is expired, and with no trusted timestamp revocation can only be checked as of now. Pass --bundle <sigstore.json> to verify it as of its Rekor signing time\n")
	}
	p("\n")
}

// verifyCert verifies a certificate against a CA, now, and extracts identity info.
func verifyCert(certPath, caPath string) (*VerifyResult, error) {
	return verifyCertAt(certPath, caPath, time.Now())
}

// verifyCertAt is verifyCert at a given time.
func verifyCertAt(certPath, caPath string, at time.Time) (*VerifyResult, error) {
	certPEM, err := os.ReadFile(certPath) // #nosec G304 - operator-supplied certificate path
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	return verifyCertPEM(certPEM, caPath, at)
}

// parseCertPEM returns the leaf (the first certificate) and a pool of the
// rest. notme task certs sit two hops below the root (root -> tier -> task)
// and notme's client writes chain.pem as leaf + tier, so without these no
// task cert can ever verify (signet-53b31c). Intermediates are untrusted:
// they only help build a path that must still end at a --ca root.
func parseCertPEM(certPEM []byte) (*x509.Certificate, *x509.CertPool, error) {
	var cert *x509.Certificate
	intermediates := x509.NewCertPool()
	for rest := certPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cert: %w", err)
		}
		if cert == nil {
			cert = c
		} else {
			intermediates.AddCert(c)
		}
	}
	if cert == nil {
		return nil, nil, fmt.Errorf("failed to decode cert PEM")
	}
	return cert, intermediates, nil
}

// verifyCertPEM is verifyCertAt on certificate bytes already read.
func verifyCertPEM(certPEM []byte, caPath string, at time.Time) (*VerifyResult, error) {
	cert, intermediates, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}

	// Read CA bundle (supports multiple PEM blocks)
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid certificates found in CA file %s", caPath)
	}

	result := &VerifyResult{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		KeyType:   keyTypeName(cert),
	}

	// Extract signet identity extensions from cert.
	//
	// THE ARC IS SHARED AND .1.5/.1.6 DISAGREE (signet-790ca1). signet, notme
	// and ley-line-open all allocate under 1.3.6.1.4.1.99999 with no registry
	// between them. Where signet reads an agent name and a scope, notme writes
	// an authMethod ("gha-oidc", "passkey", ...) and a 32-byte peer binding.
	// Measured before this guard existed: a notme certificate verified here
	// reported Agent = "gha-oidc" and a Scope of 32 bytes of SHA-256. Both
	// facts were invented, which is worse than reporting nothing -- an operator
	// reading this output, or a caller branching on result.Agent, is told a
	// workload identity is a named agent.
	//
	// So the profile is decided from the cert's own SIGNED extensions, the
	// shape ley-line-open adopted for the same collision (its PR #489): a
	// certificate carrying notme's .1.8 principal-kind marker is a notme
	// certificate, and its .1.5/.1.6 are NEVER reported as agent and scope.
	// .1.1 is the one slot all three allocations agree on, so the subject is
	// still read.
	//
	// Why .1.8 and not .1.1/.1.2 -- which is how LLO discriminates: signet's
	// own authority writes .1.1 AND .1.2 too (cmd/signet/authority_identity.go),
	// so those cannot tell the two apart here. notme emits .1.8 on every mint
	// path and nothing else under this arc claims it.
	//
	// This is a READ-SIDE fix and deliberately not a renumbering. notme cannot
	// vacate .1.6: cloister's WASM verifier already parses notme certificates
	// at this arc and reads the peer binding from it, so moving the number
	// would break a shipped consumer to tidy an allocation. Changing what this
	// verifier concludes costs no certificate bytes anywhere.
	oidSubject := asn1.ObjectIdentifier(sigid.OIDSubject)
	oidAgent := asn1.ObjectIdentifier(sigid.OIDAgentName)
	oidScope := asn1.ObjectIdentifier(sigid.OIDScope)
	notmeProfile := sigid.IsNotmeProfile(cert)
	oidTaskScope := asn1.ObjectIdentifier(sigid.OIDTaskScope)

	for _, ext := range cert.Extensions {
		val := extractExtValue(ext.Value)
		switch {
		case ext.Id.Equal(oidSubject):
			result.Owner = val
		case ext.Id.Equal(oidAgent):
			if !notmeProfile {
				result.Agent = val
			}
		case ext.Id.Equal(oidScope):
			if !notmeProfile {
				result.Scope = val
			}
		case ext.Id.Equal(oidTaskScope):
			var ts struct {
				Task     string `asn1:"utf8"`
				GoalHash []byte
			}
			if rest, err := asn1.Unmarshal(ext.Value, &ts); err == nil && len(rest) == 0 {
				result.Task = ts.Task
			}
		}
	}

	// On a notme task cert .1.1 is the TASK id, not the sponsor. The sponsor
	// is the tier principal whose identity URI the task's extends:
	// <tier identity>/<task> (signet-53b31c).
	if result.Task != "" {
		result.Owner = ""
		for _, u := range cert.URIs {
			s := u.String()
			if i := strings.LastIndex(s, "/"); i > 0 && s[i+1:] == result.Task {
				result.Owner = s[:i]
				break
			}
		}
	}

	// Verify chain
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   at,
	})
	if err != nil {
		result.Valid = false
		result.Reason = err.Error()
		var inv x509.CertificateInvalidError
		result.expired = errors.As(err, &inv) && inv.Reason == x509.Expired
		return result, nil
	}

	result.Valid = true
	result.chain = chains[0]
	result.Remaining = cert.NotAfter.Sub(at)
	return result, nil
}

// maxExtensionValueLen bounds how much data we'll attempt to decode or print
// from a certificate extension, to avoid terminal flooding on untrusted input.
const maxExtensionValueLen = 4096

// extractExtValue tries ASN.1 UTF8String first (only when the tag byte matches),
// then falls back to interpreting raw bytes as a string. Rejects oversized values
// and verifies DER was fully consumed to avoid misinterpreting raw bytes as ASN.1.
func extractExtValue(raw []byte) string {
	if len(raw) == 0 || len(raw) > maxExtensionValueLen {
		return ""
	}

	// Only attempt ASN.1 decode if the first byte is the UTF8String tag (0x0c).
	// This avoids misinterpreting raw bytes that coincidentally parse as DER.
	if raw[0] == 0x0c {
		var s string
		if rest, err := asn1.Unmarshal(raw, &s); err == nil && len(rest) == 0 {
			return s
		}
	}

	// Fallback: treat bounded raw bytes as a string (Go authority encoding).
	return string(raw)
}

// verifyLegacyCutoff resolves --legacy-cutoff and NOTME_LEGACY_CUTOFF as
// notme's task-cert verify does: the flag wins, a flag given with no value
// is an error, an empty env var is unset, and anything but an ISO date is an
// error rather than "no cutoff".
func verifyLegacyCutoff(cmd *cobra.Command) (*time.Time, error) {
	var flag *string
	if f := cmd.Flags().Lookup("legacy-cutoff"); f != nil && f.Changed {
		v := f.Value.String()
		flag = &v
	}
	return sigid.ResolveLegacyCutoff(flag, os.Getenv("NOTME_LEGACY_CUTOFF"))
}

// checkTaskCriteria applies notme's criteria rules (signet-be49b9) to a
// verified chain, and marks the result invalid on a misfit.
//
// The tier is the leaf's issuer when that is not the root: notme task certs
// sit at root -> tier -> task. Which certificates are judged:
//   - any chain where the leaf or its tier carries .1.10;
//   - a notme-profile (.1.8) chain with a tier, which without .1.10 is a
//     legacy task, subject to the cutoff.
//
// A certificate the root issues directly with no .1.10 (signet's own
// authority, notme's /cert/gha bridge certs) is not a task and is not
// judged: notme's task-cert verify only ever judges a task under a tier, and
// the cutoff exists to retire pre-criteria TASKS.
func checkTaskCriteria(result *VerifyResult, at time.Time, legacyCutoff *time.Time) {
	leaf := result.chain[0]
	var tier *x509.Certificate
	if len(result.chain) >= 3 {
		tier = result.chain[1]
	}
	_, leafHas, _ := sigid.ReadCriteria(leaf)
	tierHas := false
	if tier != nil {
		_, tierHas, _ = sigid.ReadCriteria(tier)
	}
	notmeTask := tier != nil && (sigid.IsNotmeProfile(leaf) || sigid.IsNotmeProfile(tier))
	if !leafHas && !tierHas && !notmeTask {
		return
	}

	v := sigid.CheckCriteria(tier, leaf, sigid.CriteriaOptions{At: at, LegacyCutoff: legacyCutoff})
	result.Criteria = CriteriaResult{Checked: true, Legacy: v.Legacy, ByTier: tier != nil}
	if !v.OK {
		// A reason can quote a scope string from the certificate; keep
		// control characters out of the terminal.
		reason := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return '?'
			}
			return r
		}, v.Reason)
		result.Criteria.Refused = reason
		result.Valid = false
		result.Reason = "criteria: " + reason
		return
	}
	if v.Criteria != nil {
		result.Criteria.ID = v.Criteria.ID()
	}
}

func keyTypeName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			switch pub.Curve {
			case elliptic.P256():
				return "ECDSA P-256"
			case elliptic.P384():
				return "ECDSA P-384"
			case elliptic.P521():
				return "ECDSA P-521"
			default:
				return "ECDSA"
			}
		}
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.RSA:
		return "RSA"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}
