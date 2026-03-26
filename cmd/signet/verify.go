package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/spf13/cobra"
)

var verifyCAPath string

var verifyCmd = &cobra.Command{
	Use:   "verify <cert.pem>",
	Short: "Verify a bridge certificate against the signet CA",
	Long: `Verify that a bridge certificate:
  1. Chains to the specified CA (or default signet CA)
  2. Is not expired
  3. Contains valid signet identity extensions

Extracts and displays: subject, owner (OID), issuer, validity, key type.`,
	Example: `  signet verify ~/.signet/mcp/rosary/cert.pem
  signet verify cert.pem --ca /etc/signet/ca.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyCAPath, "ca", "", "CA certificate PEM file (default: ~/.signet/ca.pem)")
	rootCmd.AddCommand(verifyCmd)
}

// VerifyResult holds the outcome of certificate verification.
type VerifyResult struct {
	Valid     bool
	Subject   string // CN
	Owner     string // OID 99999.1.1 (sponsor identity)
	Agent     string // OID 99999.1.3 (agent name, empty for human certs)
	Scope     string // OID 99999.1.4 (scope restriction, empty if unrestricted)
	Issuer    string // Issuer CN
	KeyType   string // "ECDSA P-256", "Ed25519", etc.
	NotBefore time.Time
	NotAfter  time.Time
	Remaining time.Duration
	Reason    string // if invalid, why
}

func runVerify(cmd *cobra.Command, args []string) error {
	certPath := args[0]

	if verifyCAPath == "" {
		// Try default location
		cfg := getConfig()
		defaultCA := filepath.Join(cfg.Home, "ca.pem")
		if _, err := os.Stat(defaultCA); err == nil {
			verifyCAPath = defaultCA
		} else {
			return fmt.Errorf("no CA specified and no default at %s\n  Use: signet verify cert.pem --ca ca.pem\n  Or:  curl -s https://your-authority/.well-known/ca-bundle.pem > %s", defaultCA, defaultCA)
		}
	}

	result, err := verifyCert(certPath, verifyCAPath)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	if result.Valid {
		fmt.Fprintf(os.Stderr, "%s Certificate valid\n", styles.Success.Render("✓"))
	} else {
		fmt.Fprintf(os.Stderr, "%s Certificate invalid: %s\n", styles.Error.Render("✗"), result.Reason)
	}

	fmt.Fprintf(os.Stderr, "  Subject:   %s\n", styles.Code.Render(result.Subject))
	if result.Agent != "" {
		fmt.Fprintf(os.Stderr, "  Agent:     %s\n", styles.Code.Render(result.Agent))
	}
	if result.Scope != "" {
		fmt.Fprintf(os.Stderr, "  Scope:     %s\n", styles.Code.Render(result.Scope))
	}
	if result.Owner != "" {
		fmt.Fprintf(os.Stderr, "  Sponsor:   %s\n", styles.Code.Render(result.Owner))
	}
	fmt.Fprintf(os.Stderr, "  Issuer:    %s\n", styles.Code.Render(result.Issuer))
	fmt.Fprintf(os.Stderr, "  Key:       %s\n", styles.Code.Render(result.KeyType))
	fmt.Fprintf(os.Stderr, "  Valid:     %s → %s\n",
		result.NotBefore.Format(time.RFC3339),
		result.NotAfter.Format(time.RFC3339))
	if result.Valid {
		fmt.Fprintf(os.Stderr, "  Remaining: %s\n", result.Remaining.Round(time.Minute))
	}
	fmt.Fprintln(os.Stderr)

	if !result.Valid {
		return fmt.Errorf("certificate verification failed: %s", result.Reason)
	}
	return nil
}

// verifyCert verifies a certificate against a CA and extracts identity info.
func verifyCert(certPath, caPath string) (*VerifyResult, error) {
	// Read cert
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
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

	// Extract signet identity extensions from cert
	oidSubject := asn1.ObjectIdentifier(sigid.OIDSubject)
	oidAgent := asn1.ObjectIdentifier(sigid.OIDAgentName)
	oidScope := asn1.ObjectIdentifier(sigid.OIDScope)
	for _, ext := range cert.Extensions {
		val := extractExtValue(ext.Value)
		switch {
		case ext.Id.Equal(oidSubject):
			result.Owner = val
		case ext.Id.Equal(oidAgent):
			result.Agent = val
		case ext.Id.Equal(oidScope):
			result.Scope = val
		}
	}

	// Verify chain
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		result.Valid = false
		result.Reason = err.Error()
		return result, nil
	}

	result.Valid = true
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
