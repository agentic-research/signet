package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cli/styles"
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
transparent commit signing integration. Each commit is signed with a
short-lived ephemeral certificate derived from your master key.

` + styles.Success.Render("What Works:") + `
  • Git commit signing (drop-in GPG replacement)
  • Ephemeral certificate generation (5-minute validity)
  • CMS/PKCS#7 signatures (OpenSSL compatible)
  • Git status output integration

` + styles.Warning.Render("Planned:") + `
  • Native signature verification (currently delegates to Git)
  • Revocation checking
  • Certificate chain validation`,
	Example: `  # Initialize Signet (one-time setup)
  signet commit --init

  # Export key ID for Git config
  signet commit --export-key-id

  # Configure Git to use Signet
  git config --global gpg.format x509
  git config --global gpg.x509.program $(which signet)
  git config --global user.signingKey $(signet commit --export-key-id)

  # Sign commits automatically
  git config --global commit.gpgSign true`,
	RunE: runCommit,
}

func init() {
	commitCmd.Flags().BoolVar(&initFlag, "init", false, "Initialize Signet configuration")
	commitCmd.Flags().BoolVar(&exportKeyFlag, "export-key-id", false, "Export the master key ID")
	commitCmd.Flags().StringVar(&verifyFile, "verify", "", "Verify signature from file")
	commitCmd.Flags().IntVar(&statusFd, "status-fd", 0, "File descriptor for GPG status output")

	// GPG compatibility flags (ignored)
	// Git passes these as combined shorthand: -bsau <keyid>
	// We need to define each individual flag
	commitCmd.Flags().BoolP("detach-sign", "b", false, "Create detached signature (default)")
	commitCmd.Flags().BoolP("sign", "s", false, "Make a signature (ignored)")
	commitCmd.Flags().BoolP("armor", "a", false, "Create ASCII armored output (ignored)")
	commitCmd.Flags().StringP("local-user", "u", "", "Use specified key (ignored)")
	commitCmd.Flags().BoolP("S-flag", "S", false, "GPG compatibility flag (ignored)")

	// Mark GPG compat flags as hidden for cleaner help output
	commitCmd.Flags().MarkHidden("sign")
	commitCmd.Flags().MarkHidden("armor")
	commitCmd.Flags().MarkHidden("local-user")
	commitCmd.Flags().MarkHidden("S-flag")

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
	}

	return cfg
}

func runCommit(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle initialization
	if initFlag {
		if err := keystore.InitializeSecure(); err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}
		fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully")
		return nil
	}

	// Handle export key ID
	if exportKeyFlag {
		keyID, err := keystore.GetKeyIDSecure()
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
		fmt.Printf("Signature verification requested for file delegated to Git: %s\n", verifyFile)
		return nil
	}

	// Load master key from OS keyring
	masterKey, err := keystore.LoadMasterKeySecure()
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
