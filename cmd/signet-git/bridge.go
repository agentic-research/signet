package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentic-research/signet/pkg/cli/keystore"
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
func createUserAttribution(homePath, email string, validityDays int) error {
	// Load master key
	masterKey, err := keystore.LoadMasterKeySecure()
	if err != nil {
		masterKey, err = keystore.LoadMasterKeyInsecure(homePath)
		if err != nil {
			return fmt.Errorf("failed to load master key: %w", err)
		}
	}

	// Generate bridge key pair (independent from master key)
	bridgePub, bridgePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate bridge key: %w", err)
	}

	// Create bridge cert signed by master key
	now := time.Now()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

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

	// Self-sign with master key as issuer
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   "Signet Master",
			Organization: []string{"Signet"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, bridgeTemplate, issuerTemplate, bridgePub, masterKey)
	if err != nil {
		return fmt.Errorf("failed to create bridge certificate: %w", err)
	}

	// Create git directory
	gitDir := filepath.Join(homePath, "git")
	if err := os.MkdirAll(gitDir, 0700); err != nil {
		return fmt.Errorf("failed to create git directory: %w", err)
	}

	// Write bridge cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-cert.pem"), certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write bridge cert: %w", err)
	}

	// Write bridge key as PKCS8
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(bridgePriv)
	if err != nil {
		return fmt.Errorf("failed to marshal bridge key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-key.pem"), keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write bridge key: %w", err)
	}

	return nil
}
