package git

import (
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/crypto/keys"
	"github.com/jamestexas/signet/pkg/lifecycle"
)

// withMasterKey wraps master key loading with lifecycle management using the loan pattern.
// It tries keyring first, then falls back to file-based storage.
func withMasterKey(cfg *config.Config, fn func(*keys.Ed25519Signer) error) error {
	// Load master key (returns *keys.Ed25519Signer)
	masterKey, err := keystore.LoadMasterKeySecure()
	if err != nil {
		// Fallback to file-based
		masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			return fmt.Errorf("failed to load master key: %w", err)
		}
	}

	// Use loan pattern to ensure Destroy() is always called
	// The zeroizer receives a pointer to the *keys.Ed25519Signer
	signerZeroizer := func(s *(*keys.Ed25519Signer)) {
		if *s != nil {
			(*s).Destroy()
		}
	}

	return lifecycle.WithSecureValue(masterKey, signerZeroizer, func(s *(*keys.Ed25519Signer)) error {
		return fn(*s)
	})
}

// SignCommit signs commit data from stdin and writes signature to stdout
// This implements the gpgsm-compatible signing interface expected by Git
func SignCommit(cfg *config.Config, localUser string, statusFd int) error {
	return withMasterKey(cfg, func(masterKey *keys.Ed25519Signer) error {
		// Read commit data from stdin
		commitData, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read commit data: %w", err)
		}

		// Create Local CA
		ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)

		// Calculate certificate validity
		certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

		// Generate ephemeral certificate
		cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
		if err != nil {
			return fmt.Errorf("failed to generate certificate: %w", err)
		}

		// Use loan pattern for ephemeral key lifecycle
		ephemeralZeroizer := func(k *(*keys.SecurePrivateKey)) {
			if *k != nil {
				(*k).Destroy()
			}
		}

		return lifecycle.WithSecureValue(secEphemeralKey, ephemeralZeroizer, func(secureEphemeral *(*keys.SecurePrivateKey)) error {
			// Extract the raw key for CMS signing
			ephemeralKey := (*secureEphemeral).Key()

			// Emit BEGIN_SIGNING before creating signature (gpgsm-compatible)
			if statusFd > 0 {
				statusFile := os.NewFile(uintptr(statusFd), "status")
				if statusFile != nil {
					if _, err := fmt.Fprintln(statusFile, "[GNUPG:] BEGIN_SIGNING"); err != nil {
						// Log to stderr but don't fail - status output is informational
						fmt.Fprintf(os.Stderr, "Warning: failed to write BEGIN_SIGNING status: %v\n", err)
					}
				}
			}

			// Create CMS signature with Ed25519
			signature, err := cms.SignData(commitData, cert, ed25519.PrivateKey(ephemeralKey))
			if err != nil {
				return fmt.Errorf("failed to sign commit: %w", err)
			}

			// Emit SIG_CREATED with certificate fingerprint (gpgsm-compatible)
			if statusFd > 0 {
				statusFile := os.NewFile(uintptr(statusFd), "status")
				if statusFile != nil {
					timestamp := time.Now().Unix()
					fpr := certHexFingerprint(cert)
					if _, err := fmt.Fprintf(statusFile, "[GNUPG:] SIG_CREATED D 22 8 00 %d %s\n", timestamp, fpr); err != nil {
						// Log to stderr but don't fail - status output is informational
						fmt.Fprintf(os.Stderr, "Warning: failed to write SIG_CREATED status: %v\n", err)
					}
				}
			}

			// Output PEM-encoded signature to stdout
			// Git expects "SIGNED MESSAGE" for x509 format (not "CMS")
			pemBlock := &pem.Block{
				Type:  "SIGNED MESSAGE",
				Bytes: signature,
			}

			if err := pem.Encode(os.Stdout, pemBlock); err != nil {
				return fmt.Errorf("failed to encode signature: %w", err)
			}

			return nil
		})
	})
}

// certHexFingerprint calculates the SHA1 fingerprint of a certificate (gpgsm-compatible)
// This is what Git expects for the fingerprint in status output
func certHexFingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return "0000000000000000000000000000000000000000"
	}
	fpr := sha1.Sum(cert.Raw) // #nosec G401 - SHA1 used for fingerprint only, not security
	return hex.EncodeToString(fpr[:])
}
