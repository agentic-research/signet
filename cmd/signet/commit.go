package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cli/styles"
	"github.com/jamestexas/signet/pkg/cms"
)

var (
	// Commit subcommand flags
	initFlag      bool
	exportKeyFlag bool
	verifyFile    string
	statusFd      int
)

var commitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Sign Git commits",
	Long: `Sign Git commits using ephemeral certificates.

This command is designed to be used as Git's gpg.x509.program for
transparent commit signing integration.`,
	RunE: runCommit,
}

func init() {
	commitCmd.Flags().BoolVar(&initFlag, "init", false, "Initialize Signet configuration")
	commitCmd.Flags().BoolVar(&exportKeyFlag, "export-key-id", false, "Export the master key ID")
	commitCmd.Flags().StringVar(&verifyFile, "verify", "", "Verify signature from file")
	commitCmd.Flags().IntVar(&statusFd, "status-fd", 0, "File descriptor for GPG status output")

	// GPG compatibility flags (ignored)
	commitCmd.Flags().String("bsau", "", "GPG compatibility flag (ignored)")
	commitCmd.Flags().Bool("S", false, "GPG compatibility flag (ignored)")
	commitCmd.Flags().Bool("detach-sign", false, "Create detached signature (default)")

	// Mark flags as hidden for cleaner help output
	commitCmd.Flags().MarkHidden("bsau")
	commitCmd.Flags().MarkHidden("S")

	rootCmd.AddCommand(commitCmd)
}

// getConfig loads configuration with flag overrides
func getConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		// Fallback to default config
		cfg = config.New(config.DefaultHome())
	}

	// Override with --home flag if provided
	if homeDir != "" {
		cfg.Home = homeDir
		cfg.KeyPath = cfg.Home + "/" + keystore.MasterKeyFile
	}

	return cfg
}

func runCommit(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle initialization
	if initFlag {
		if err := keystore.Initialize(cfg.Home); err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}
		fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully")
		fmt.Println(styles.Subtle.Render("  Master key stored in: ") + styles.Code.Render(cfg.Home))
		return nil
	}

	// Handle export key ID
	if exportKeyFlag {
		keyID, err := keystore.GetKeyID(cfg.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to get key ID: %w", err)
		}
		// Output raw key ID for Git (no styling for machine-readable output)
		fmt.Println(keyID)
		return nil
	}

	// Handle verify flag (for Git compatibility)
	// We don't verify - that's gpgsm's job in the Git workflow
	if verifyFile != "" {
		// Git passes: --verify <signature-file> <data-file>
		// Just exit successfully to let Git continue
		return nil
	}

	// Load master key
	masterKey, err := keystore.LoadMasterKey(cfg.KeyPath)
	if err != nil {
		msg := styles.Info.Render("→") + " Run " + styles.Code.Render("signet commit --init") + " to initialize\n"
		fmt.Fprint(os.Stderr, msg)
		return fmt.Errorf("failed to load master key: %w", err)
	}
	defer masterKey.Destroy()

	// Read commit data from stdin
	commitData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read commit data: %w", err)
	}

	// Create Local CA
	ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)

	// Calculate certificate validity
	certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

	// Generate ephemeral certificate with secure key handling
	cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}
	defer secEphemeralKey.Destroy() // Ensure ephemeral key is zeroed when done

	// Extract the raw key for CMS signing (will be zeroed via defer above)
	ephemeralKey := secEphemeralKey.Key()

	// Create CMS signature with Ed25519
	signature, err := cms.SignData(commitData, cert, ed25519.PrivateKey(ephemeralKey))
	if err != nil {
		return fmt.Errorf("failed to sign commit: %w", err)
	}

	// If Git requested status output, emit the required status line
	if statusFd > 0 {
		// Get the key ID (fingerprint) from arguments after flags
		keyFpr := ""
		if len(args) > 0 {
			keyFpr = args[0]
		}

		// Create status file from descriptor
		statusFile := os.NewFile(uintptr(statusFd), "status")
		if statusFile != nil {
			// Format: [GNUPG:] SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <fingerprint>
			// type: D (detached)
			// pk_algo: 22 (EdDSA)
			// hash_algo: 8 (SHA256)
			// class: 00 (standard)
			timestamp := time.Now().Unix()
			fmt.Fprintf(statusFile, "[GNUPG:] SIG_CREATED D 22 8 00 %d %s\n", timestamp, keyFpr)
		}
	}

	// Output PEM-encoded signature to stdout
	pemBlock := &pem.Block{
		Type:  "CMS",
		Bytes: signature,
	}

	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		return fmt.Errorf("failed to encode signature: %w", err)
	}

	return nil
}
