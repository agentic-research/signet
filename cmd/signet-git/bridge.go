package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	"github.com/agentic-research/signet/pkg/cli/keystore"
	"github.com/agentic-research/signet/pkg/crypto/keys"
)

var (
	initEmail          string
	bridgeValidityDays int
)

func addBridgeFlags(initCmd *cobra.Command) {
	initCmd.Flags().StringVar(&initEmail, "email", "", "User email for attribution (enables GitHub verification)")
	initCmd.Flags().IntVar(&bridgeValidityDays, "bridge-validity-days", 365, "Bridge certificate validity in days")
}

func exportBridgeCertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-bridge-cert",
		Short: "Export the user attribution certificate for GitHub",
		Long: `Export the bridge certificate for uploading to GitHub.

The bridge certificate contains your email and enables GitHub "Verified" badges.

Upload steps:
  1. Run this command and save the output
  2. Go to https://github.com/settings/keys
  3. Click "New GPG Key"
  4. Paste the certificate and save`,
		Example: `  # Export certificate to file
  signet-git export-bridge-cert > bridge.pem

  # Copy to clipboard (macOS)
  signet-git export-bridge-cert | pbcopy`,
		RunE:          runExportBridgeCert,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runExportBridgeCert(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	if err := cfg.ValidateHomePathRuntime(); err != nil {
		return fmt.Errorf("invalid home directory: %w", err)
	}
	certPath := filepath.Join(cfg.Home, "git", "bridge-cert.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("bridge certificate not found\n\n" +
			"User attribution not configured. Run:\n" +
			"  signet-git init --email your@email.com")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read bridge certificate: %w", err)
	}

	// Raw PEM output (no styling for machine-readable output)
	fmt.Print(string(certPEM))
	return nil
}

// createUserAttribution generates a bridge cert and key for email attribution.
// Called from runInit when --email is provided.
//
// Uses LocalCA for issuer template construction (consistent with library API).
// The bridge cert has email in CN + SAN for GitHub badge matching.
func createUserAttribution(homePath, issuerDID, email string, validityDays int) error {
	if validityDays <= 0 {
		return fmt.Errorf("bridge certificate validity must be positive, got %d days", validityDays)
	}

	// Load master key with zeroization on all exit paths
	masterKey, err := keystore.LoadMasterKeySecure()
	if err != nil {
		masterKey, err = keystore.LoadMasterKeyInsecure(homePath)
		if err != nil {
			return fmt.Errorf("failed to load master key: %w", err)
		}
	}
	defer masterKey.Destroy()

	// Use LocalCA for consistent issuer template (#5)
	ca := attestx509.NewLocalCA(masterKey, issuerDID)

	// Generate bridge key pair (independent from master key)
	bridgePub, bridgePrivRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate bridge key: %w", err)
	}
	// Wrap bridge key for zeroization (#2)
	bridgePriv := keys.NewSecurePrivateKey(bridgePrivRaw)
	defer bridgePriv.Destroy()

	// Create bridge cert template with email for GitHub verification.
	// This differs from IssueBridgeCertificate (which uses capability extensions)
	// because the CLI flow needs email in CN + SAN for GitHub badge matching,
	// while the authority flow needs capability URIs.
	serialNumber, err := attestx509.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	bridgeTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"Signet"},
		},
		EmailAddresses:        []string{email},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Use LocalCA to issue the bridge cert (consistent issuer template + key IDs)
	cert, err := ca.IssueClientCertificate(bridgeTemplate, bridgePub)
	if err != nil {
		return fmt.Errorf("failed to create bridge certificate: %w", err)
	}

	// Create git directory
	gitDir := filepath.Join(homePath, "git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		return fmt.Errorf("failed to create git directory: %w", err)
	}

	// Write bridge cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-cert.pem"), certPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write bridge cert: %w", err)
	}

	// Write bridge key as PKCS8 with zeroization of intermediate buffers (#2)
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(bridgePriv.Key())
	if err != nil {
		return fmt.Errorf("failed to marshal bridge key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	// Zeroize intermediate DER bytes
	for i := range pkcs8Key {
		pkcs8Key[i] = 0
	}
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-key.pem"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write bridge key: %w", err)
	}
	// Zeroize PEM bytes after writing
	for i := range keyPEM {
		keyPEM[i] = 0
	}

	return nil
}
