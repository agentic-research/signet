package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/spf13/cobra"
)

var (
	verifyCAPath    string
	verifyAuthority string
	verifyOffline   bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify <cert.pem>",
	Short: "Verify a bridge certificate against the signet CA, including revocation",
	Long: `Verify that a bridge certificate:
  1. Chains to the specified CA (or default signet CA)
  2. Is not expired
  3. Contains valid signet identity extensions
  4. Has not been revoked: its CA epoch matches the authority's signed CA bundle

The cert file may hold the leaf followed by intermediates (for a notme task
certificate: task, then the tier). Intermediates only help build the path;
it must still end at a certificate in --ca.

Revocation. After the chain verifies, signet fetches the authority's signed
CA bundle from <authority>/internal/ca-bundle and checks:
  - the bundle signature, against the --ca root the chain ended at (the
    pinned anchor; the network is not trusted);
  - freshness: the bundle must be under an hour old;
  - rollback: its seqno must not be lower than the last one seen (kept in
    <signet home>/revocation);
  - the root key is still in the bundle;
  - every certificate below the root carries a CA epoch (OID
    1.3.6.1.4.1.99999.1.4) equal to the bundle's epoch. An older epoch means
    the authority revoked it (for notme: POST /admin/revoke-epoch).
Any failure, including an unreachable authority, makes the certificate
invalid. The authority defaults to https://auth.<trust domain> from the
certificate's wimse:// URI; set it with --authority.

--offline skips the revocation check. The output then says "revocation NOT
checked": the certificate may already be revoked.

Extracts and displays: subject, task, sponsor, issuer, validity, key type,
and the revocation result.`,
	Example: `  signet verify ~/.signet/mcp/rosary/cert.pem
  signet verify cert.pem --ca /etc/signet/ca.pem
  signet verify task/chain.pem --ca root.pem
  signet verify cert.pem --ca root.pem --authority https://auth.notme.bot
  signet verify cert.pem --ca root.pem --offline`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyCAPath, "ca", "", "CA certificate PEM file (default: ~/.signet/ca.pem)")
	verifyCmd.Flags().StringVar(&verifyAuthority, "authority", "", "Authority URL serving /internal/ca-bundle for the revocation check (default: https://auth.<trust domain> from the cert's wimse:// URI)")
	verifyCmd.Flags().BoolVar(&verifyOffline, "offline", false, "Skip the revocation check (output says \"revocation NOT checked\")")
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

	// chain is the verified path, leaf first and the --ca root last. Set
	// only when the chain verified; the revocation check reads it.
	chain []*x509.Certificate
}

// RevocationResult records what the revocation check established.
type RevocationResult struct {
	Checked   bool          // the bundle was fetched, verified and every epoch matched
	Authority string        // where the bundle came from
	Epoch     uint64        // the authority's current epoch, from the signed bundle
	BundleAge time.Duration // age of the bundle at check time
}

// verifyOptions carries everything a verification run needs, so tests can
// drive the same code path as the command.
type verifyOptions struct {
	caPath    string
	authority string       // --authority; empty means derive from the cert
	offline   bool         // --offline: skip the revocation check
	client    *http.Client // fetches the CA bundle
	stateDir  string       // holds the last-seen bundle seqno (rollback protection)
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

	return verifyAndReport(cmd.Context(), os.Stderr, certPath, verifyOptions{
		caPath:    verifyCAPath,
		authority: verifyAuthority,
		offline:   verifyOffline,
		client:    &http.Client{Timeout: 15 * time.Second},
		stateDir:  filepath.Join(cfg.Home, "revocation"),
	})
}

// verifyAndReport verifies the chain, then (unless offline) revocation, and
// writes the human-readable result to w. It returns an error whenever the
// certificate is not valid, so the exit status is non-zero.
func verifyAndReport(ctx context.Context, w io.Writer, certPath string, opts verifyOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := verifyCert(certPath, opts.caPath)
	if err != nil {
		return err
	}

	// Revocation runs only on a chain that verified: the bundle is checked
	// against the root the chain ended at, and a cert that does not chain is
	// already invalid. Fail closed: any error here makes the cert invalid.
	if result.Valid && !opts.offline {
		if err := checkRevocation(ctx, result, opts); err != nil {
			result.Valid = false
			result.Reason = "revocation check failed: " + err.Error()
		}
	}

	renderVerifyResult(w, result, opts.offline)

	if !result.Valid {
		return fmt.Errorf("certificate verification failed: %s", result.Reason)
	}
	return nil
}

func renderVerifyResult(w io.Writer, result *VerifyResult, offline bool) {
	// Output is best-effort (a terminal); a write error has nowhere to go.
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("\n")
	switch {
	case result.Valid && offline:
		p("%s Certificate valid (revocation NOT checked)\n", styles.Success.Render("✓"))
	case result.Valid:
		p("%s Certificate valid\n", styles.Success.Render("✓"))
	default:
		p("%s Certificate invalid: %s\n", styles.Error.Render("✗"), result.Reason)
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
	if result.Valid {
		p("  Remaining: %s\n", result.Remaining.Round(time.Minute))
	}
	switch {
	case offline:
		p("  Revocation: revocation NOT checked (--offline): a revoked certificate still shows as valid\n")
	case result.Revocation.Checked:
		p("  Revocation: checked (epoch %d, bundle age %ds, %s)\n",
			result.Revocation.Epoch,
			int64(result.Revocation.BundleAge.Seconds()),
			result.Revocation.Authority)
	}
	p("\n")
}

// verifyCert verifies a certificate against a CA and extracts identity info.
func verifyCert(certPath, caPath string) (*VerifyResult, error) {
	// Read cert
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	// The first certificate is the leaf; any that follow are intermediates.
	// notme task certs sit two hops below the root (root -> tier -> task) and
	// notme's client writes chain.pem as leaf + tier, so without these no
	// task cert can ever verify (signet-53b31c). Intermediates are untrusted:
	// they only help build a path that must still end at a --ca root.
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
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		if cert == nil {
			cert = c
		} else {
			intermediates.AddCert(c)
		}
	}
	if cert == nil {
		return nil, fmt.Errorf("failed to decode cert PEM")
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
		CurrentTime:   time.Now(),
	})
	if err != nil {
		result.Valid = false
		result.Reason = err.Error()
		return result, nil
	}

	result.Valid = true
	result.chain = chains[0]
	result.Remaining = time.Until(cert.NotAfter)
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
