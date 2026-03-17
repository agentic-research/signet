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

	"github.com/agentic-research/go-cms/pkg/cms"
	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	"github.com/agentic-research/signet/pkg/cli/config"
	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/agentic-research/signet/pkg/lifecycle"
)

// SignCommit signs commit data from stdin and writes signature to stdout.
// This implements the gpgsm-compatible signing interface expected by Git.
// If a bridge cert is present (Level 1+), the CMS signature includes it
// as an intermediate cert: master → bridge → ephemeral → commit.
func SignCommit(cfg *config.Config, localUser string, statusFd int) error {
	if cfg.Algorithm != "" && algorithm.Algorithm(cfg.Algorithm) != algorithm.Ed25519 {
		return fmt.Errorf("git signing requires Ed25519; configured algorithm %q is not supported for git commits. Use `signet sign` for %s signing", cfg.Algorithm, cfg.Algorithm)
	}

	identity, err := LoadIdentity(cfg)
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}
	defer identity.Destroy()

	commitData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read commit data: %w", err)
	}

	certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

	if identity.HasUserAttribution() {
		return signWithBridgeCert(identity, commitData, certValidity, statusFd)
	}
	return signLevel0(identity, commitData, certValidity, statusFd)
}

// signLevel0 signs using only the machine master key (existing 2-cert chain).
func signLevel0(id *Identity, data []byte, validity time.Duration, statusFd int) error {
	ca := attestx509.NewLocalCA(id.MasterKey, id.MachineID)

	cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(validity)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	return withEphemeralKey(secEphemeralKey, func(ephemeralKey ed25519.PrivateKey) error {
		return signAndOutput(data, cert, ephemeralKey, nil, statusFd)
	})
}

// signWithBridgeCert signs using the bridge cert chain (3-cert chain).
// Chain: master key → bridge cert → ephemeral cert → commit signature.
func signWithBridgeCert(id *Identity, data []byte, validity time.Duration, statusFd int) error {
	// Extract raw key since SecurePrivateKey doesn't implement crypto.Signer
	bridgeRawKey := ed25519.PrivateKey(id.BridgeKey.Key())
	bridgeCA := attestx509.NewLocalCA(bridgeRawKey, id.MachineID)

	cert, _, secEphemeralKey, err := bridgeCA.IssueCodeSigningCertWithParent(id.BridgeCert, validity)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral cert under bridge: %w", err)
	}

	return withEphemeralKey(secEphemeralKey, func(ephemeralKey ed25519.PrivateKey) error {
		intermediateCerts := []*x509.Certificate{id.BridgeCert}
		return signAndOutput(data, cert, ephemeralKey, intermediateCerts, statusFd)
	})
}

// signAndOutput creates a CMS signature and writes it to stdout.
func signAndOutput(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey,
	intermediateCerts []*x509.Certificate, statusFd int) error {

	emitStatus(statusFd, "[GNUPG:] BEGIN_SIGNING")

	opts := cms.SignOptions{
		IntermediateCerts: intermediateCerts,
	}
	signature, err := cms.SignDataWithOptions(data, cert, privateKey, opts)
	if err != nil {
		return fmt.Errorf("failed to sign commit: %w", err)
	}

	emitStatus(statusFd, fmt.Sprintf("[GNUPG:] SIG_CREATED D 22 8 00 %d %s",
		time.Now().Unix(), certHexFingerprint(cert)))

	pemBlock := &pem.Block{
		Type:  "SIGNED MESSAGE",
		Bytes: signature,
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		return fmt.Errorf("failed to encode signature: %w", err)
	}
	return nil
}

// withEphemeralKey wraps ephemeral key usage with lifecycle management.
func withEphemeralKey(secKey *keys.SecurePrivateKey, fn func(ed25519.PrivateKey) error) error {
	zeroizer := func(k *(*keys.SecurePrivateKey)) {
		if *k != nil {
			(*k).Destroy()
		}
	}
	return lifecycle.WithSecureValue(secKey, zeroizer, func(sk *(*keys.SecurePrivateKey)) error {
		return fn((*sk).Key())
	})
}

// emitStatus writes a gpgsm-compatible status line to the status fd.
func emitStatus(statusFd int, line string) {
	if statusFd <= 0 {
		return
	}
	statusFile := os.NewFile(uintptr(statusFd), "status")
	if statusFile != nil {
		if _, err := fmt.Fprintln(statusFile, line); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write status: %v\n", err)
		}
	}
}

// certHexFingerprint calculates the SHA1 fingerprint of a certificate (gpgsm-compatible)
func certHexFingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return "0000000000000000000000000000000000000000"
	}
	fpr := sha1.Sum(cert.Raw) // #nosec G401 - SHA1 used for fingerprint only, not security
	return hex.EncodeToString(fpr[:])
}
