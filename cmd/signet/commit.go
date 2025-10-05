package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/zalando/go-keyring"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cli/styles"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

var (
	// Commit subcommand flags
	initFlag      bool
	exportKeyFlag bool
	verifyFile    string
	statusFd      int
	insecureFlag  bool // Use file-based storage instead of OS keyring
	migrateFlag   bool // Migrate from file-based to keyring storage
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
	commitCmd.Flags().BoolVar(&insecureFlag, "insecure", false, "Use file-based key storage (not recommended)")
	commitCmd.Flags().BoolVar(&migrateFlag, "migrate", false, "Migrate key from file storage to OS keyring")

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
		cfg.KeyPath = cfg.Home + "/" + keystore.MasterKeyFile
	}

	return cfg
}

func runCommit(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle migration from file to keyring
	if migrateFlag {
		return migrateToKeyring(cfg)
	}

	// Handle initialization
	if initFlag {
		if insecureFlag {
			// Use legacy file-based storage
			if err := keystore.Initialize(cfg.Home); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}
			fmt.Println(styles.Warning.Render("⚠") + " Initialized with INSECURE file-based storage")
			fmt.Println(styles.Subtle.Render("  Master key stored in: ") + styles.Code.Render(cfg.Home))
			fmt.Println(styles.Subtle.Render("  Consider using secure keyring storage (remove --insecure flag)"))
		} else {
			// Use secure OS keyring storage (default)
			if err := keystore.InitializeSecure(); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}
			fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully with secure OS keyring storage")
		}
		return nil
	}

	// Handle export key ID
	if exportKeyFlag {
		var keyID string
		var err error

		if insecureFlag {
			keyID, err = keystore.GetKeyID(cfg.KeyPath)
		} else {
			keyID, err = keystore.GetKeyIDSecure()
			// Fallback to file-based if keyring fails
			if err != nil {
				keyID, err = keystore.GetKeyID(cfg.KeyPath)
			}
		}

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

	// Load master key (try keyring first, fallback to file)
	var masterKey *keys.Ed25519Signer
	var err error

	if insecureFlag {
		masterKey, err = keystore.LoadMasterKey(cfg.KeyPath)
	} else {
		masterKey, err = keystore.LoadMasterKeySecure()
		// Fallback to file-based if keyring fails
		if err != nil {
			masterKey, err = keystore.LoadMasterKey(cfg.KeyPath)
		}
	}

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

// migrateToKeyring migrates a key from file-based storage to OS keyring
func migrateToKeyring(cfg *config.Config) error {
	keyPath := filepath.Join(cfg.Home, keystore.MasterKeyFile)

	// Check if file-based key exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("no file-based key found at %s", keyPath)
	}

	// Check if keyring key already exists
	_, err := keystore.GetKeyIDSecure()
	if err == nil {
		return fmt.Errorf("key already exists in OS keyring - migration not needed")
	}

	// Load the file-based key
	signer, err := keystore.LoadMasterKey(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load file-based key: %w", err)
	}
	defer signer.Destroy()

	// Get the public key for verification
	filePubKey := signer.Public().(ed25519.PublicKey)

	// Store in keyring (we need to extract the seed)
	// Read the file directly to get the seed
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return fmt.Errorf("invalid key file format")
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return fmt.Errorf("invalid seed size")
	}

	// Reconstruct the full key to get public key
	privateKey := ed25519.NewKeyFromSeed(block.Bytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Store the seed in keyring using the existing secure storage
	seedHex := fmt.Sprintf("%x", block.Bytes)
	if err := keyring.Set(keystore.ServiceName, keystore.MasterKeyItem, seedHex); err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	// Zero sensitive data
	for i := range block.Bytes {
		block.Bytes[i] = 0
	}
	for i := range privateKey {
		privateKey[i] = 0
	}

	// Verify the migration by loading from keyring
	verifySigner, err := keystore.LoadMasterKeySecure()
	if err != nil {
		return fmt.Errorf("migration verification failed - could not load from keyring: %w", err)
	}
	defer verifySigner.Destroy()

	verifyPubKey := verifySigner.Public().(ed25519.PublicKey)
	if !ed25519.PublicKey(filePubKey).Equal(verifyPubKey) {
		return fmt.Errorf("migration verification failed - public keys don't match")
	}

	fmt.Println(styles.Success.Render("✓") + " Successfully migrated key to OS keyring")
	fmt.Println(styles.Subtle.Render("  Public key: ") + fmt.Sprintf("%x", publicKey))
	fmt.Println()
	fmt.Println(styles.Info.Render("→") + " The file-based key is still present at: " + styles.Code.Render(keyPath))
	fmt.Println(styles.Subtle.Render("  You can delete it manually after verifying the migration"))
	fmt.Println(styles.Subtle.Render("  To test: ") + styles.Code.Render("signet commit --export-key-id"))

	return nil
}
