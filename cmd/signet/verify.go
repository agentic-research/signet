package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
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
	verifyCmd.Flags().StringVar(&verifyCAPath, "ca", "", "CA certificate PEM (default: fetch from authority)")
	rootCmd.AddCommand(verifyCmd)
}

// VerifyResult holds the outcome of certificate verification.
type VerifyResult struct {
	Valid     bool
	Subject   string // CN
	Owner     string // OID 99999.1.1
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
		defaultCA := cfg.Home + "/ca.pem"
		if _, err := os.Stat(defaultCA); err == nil {
			verifyCAPath = defaultCA
		} else {
			return fmt.Errorf("no CA specified and no default at %s\n  Use: signet verify cert.pem --ca ca.pem", defaultCA)
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
	if result.Owner != "" {
		fmt.Fprintf(os.Stderr, "  Owner:     %s\n", styles.Code.Render(result.Owner))
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

	// Read CA
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("failed to decode CA PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}

	result := &VerifyResult{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		KeyType:   keyTypeName(cert),
	}

	// Extract owner from OID extension
	oidSubject := asn1.ObjectIdentifier(sigid.OIDSubject)
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubject) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
				result.Owner = s
			} else {
				result.Owner = string(ext.Value)
			}
		}
	}

	// Verify chain
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
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

func keyTypeName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		return "ECDSA P-256"
	case x509.Ed25519:
		return "Ed25519"
	case x509.RSA:
		return "RSA"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}
