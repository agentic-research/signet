package git

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
)

// VerifySignature verifies a CMS signature for Git compatibility
func VerifySignature(cfg *config.Config, sigFile, dataFile string, statusFd int) error {
	// Determine status writer
	statusWriter := getStatusWriter(statusFd)

	// Load master key to create the CA certificate for verification
	masterKey, err := keystore.LoadMasterKeySecure()
	if err != nil {
		// Fallback to file-based if keyring fails
		masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			return fmt.Errorf("failed to load master key for verification: %w", err)
		}
	}
	defer masterKey.Destroy()

	// Read signature file
	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Try to decode as PEM first
	block, _ := pem.Decode(sigData)
	if block != nil {
		sigData = block.Bytes
	} else {
		// If not PEM, try base64 decode (Git stores signatures as base64 without PEM headers)
		decoded, err := base64.StdEncoding.DecodeString(string(sigData))
		if err == nil && len(decoded) > 0 {
			sigData = decoded
		}
		// If base64 decode fails, assume it's already DER and use as-is
	}

	// Read commit data - from file if specified, otherwise stdin
	var commitData []byte
	if dataFile == "" || dataFile == "-" {
		commitData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read commit data from stdin: %w", err)
		}
	} else {
		commitData, err = os.ReadFile(dataFile)
		if err != nil {
			return fmt.Errorf("failed to read commit data from file: %w", err)
		}
	}

	// Fail fast if no data to verify
	if len(commitData) == 0 {
		_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] BADSIG 0000000000000000 \"Signet X509\"\n")
		return fmt.Errorf("no data to verify")
	}

	// Create the CA certificate from our master key to use as trust root
	ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)
	caTemplate := ca.CreateCACertificateTemplate()
	if caTemplate == nil {
		return fmt.Errorf("failed to create CA template")
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(
		nil,
		caTemplate,
		caTemplate,
		masterKey.Public(),
		masterKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create cert pool with our CA as the trust root
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Skip time validation for Git commits with ephemeral certs
	// Git commits are historical artifacts that need indefinite verification.
	// We verify the chain of trust (cert was signed by our CA) rather than expiry time.
	opts := cms.VerifyOptions{
		Roots:              roots,
		KeyUsages:          []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SkipTimeValidation: true, // Allow verification of expired ephemeral certs
	}

	// Verify the signature
	certs, err := cms.Verify(sigData, commitData, opts)
	if err != nil {
		// Output BADSIG status on verification failure
		_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] BADSIG 0000000000000000000000000000000000000000 \"Signet X509\"\n")
		_, _ = fmt.Fprintf(os.Stderr, "Signature verification failed: %v\n", err)
		return fmt.Errorf("verification failed: %w", err)
	}

	// Extract metadata for status output
	var signerCert *x509.Certificate
	if len(certs) > 0 {
		signerCert = certs[0]
	}

	// Use SHA1 fingerprint (gpgsm-compatible) for both GOODSIG and VALIDSIG
	fpr := certHexFingerprint(signerCert)
	uid := "Signet X509"
	if signerCert != nil && signerCert.Subject.CommonName != "" {
		uid = signerCert.Subject.CommonName
	}

	// Write GPG status output in required format
	_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] NEWSIG\n")
	_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] GOODSIG %s \"%s\"\n", fpr, uid)
	_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] VALIDSIG %s 0 0 0 0 0 0 0 0 0 0\n", fpr)
	_, _ = fmt.Fprintf(statusWriter, "[GNUPG:] TRUST_FULLY 0 shell\n")

	_, _ = fmt.Fprintln(os.Stderr, "✓ Signature verified successfully")
	return nil
}

// getStatusWriter returns an io.Writer for GNUPG status output
// Matches gpgsm/gitsign behavior for fd mapping
func getStatusWriter(statusFd int) io.Writer {
	const (
		unixStdout = 1
		unixStderr = 2
	)

	// Git always passes fd 1 or 2 even on Windows
	switch statusFd {
	case 0:
		return os.Stdout
	case unixStdout:
		return os.Stdout
	case unixStderr:
		return os.Stderr
	default:
		return os.NewFile(uintptr(statusFd), "status")
	}
}
