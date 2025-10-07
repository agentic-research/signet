package main

import (
	"crypto/ed25519"
	"crypto/x509"
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
	initFlag         bool
	initInsecureFlag bool
	exportKeyFlag    bool
	verifyFile       string
	statusFd         int
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
	commitCmd.Flags().BoolVar(&initInsecureFlag, "insecure", false, "Initialize with file-based storage (for testing)")
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
		if initInsecureFlag {
			if err := keystore.InitializeInsecure(cfg.Home); err != nil {
				return fmt.Errorf("insecure initialization failed: %w", err)
			}
			fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully (insecure file-based storage)")
		} else {
			if err := keystore.InitializeSecure(); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}
			fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully")
		}
		return nil
	}

	// Handle export key ID
	if exportKeyFlag {
		keyID, err := keystore.GetKeyIDSecure()
		if err != nil {
			// Fallback to file-based
			keyID, err = keystore.GetKeyIDInsecure(cfg.Home)
			if err != nil {
				return fmt.Errorf("failed to get key ID: %w", err)
			}
		}
		// Output raw key ID for Git (no styling for machine-readable output)
		fmt.Println(keyID)
		return nil
	}

	// Handle verify flag (for Git compatibility)
	if verifyFile != "" {
		// Git passes: --verify <signature-file> <data-file>
		// If data-file is "-", read from stdin; otherwise read from file
		dataFile := ""
		if len(args) > 0 {
			dataFile = args[0]
		}
		return verifySignature(verifyFile, dataFile, statusFd)
	}

	// Load master key from OS keyring
	masterKey, err := keystore.LoadMasterKeySecure()
	// Fallback to file-based if keyring fails
	if err != nil {
		fmt.Fprintln(os.Stderr, styles.Warning.Render("⚠")+" Keyring access failed, falling back to file-based storage")
		masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			msg := styles.Info.Render("→") + " Run " + styles.Code.Render("signet commit --init") + " to initialize\n"
			fmt.Fprint(os.Stderr, msg)
			return fmt.Errorf("failed to load master key: %w", err)
		}
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

// verifySignature verifies a CMS signature for Git compatibility
func verifySignature(sigFile, dataFile string, statusFd int) error {
	// Get configuration
	cfg := getConfig()

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

	// Decode PEM if present
	block, _ := pem.Decode(sigData)
	if block != nil {
		sigData = block.Bytes
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

	opts := cms.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// Don't check time validity for now (ephemeral certs may have expired)
		// CurrentTime: time.Time{},
	}

	// Verify the signature
	certs, err := cms.Verify(sigData, commitData, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signature verification failed: %v\n", err)
		return fmt.Errorf("verification failed: %w", err)
	}

	// Write GPG status output if requested
	if statusFd > 0 {
		statusFile := os.NewFile(uintptr(statusFd), "status")
		if statusFile != nil {
			// Format: [GNUPG:] GOODSIG <long_keyid_or_fingerprint> <uid>
			keyID := ""
			if len(certs) > 0 && certs[0].Subject.CommonName != "" {
				keyID = certs[0].Subject.CommonName
			}
			if _, err := fmt.Fprintf(statusFile, "[GNUPG:] GOODSIG %s %s\n", keyID, keyID); err != nil {
				return fmt.Errorf("failed to write GPG status: %w", err)
			}
			if _, err := fmt.Fprintf(statusFile, "[GNUPG:] VALIDSIG %s\n", keyID); err != nil {
				return fmt.Errorf("failed to write GPG status: %w", err)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "✓ Signature verified successfully")
	return nil
}
