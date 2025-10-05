package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cli/styles"
)

var (
	// Sign subcommand flags
	signFormat     string
	signOutput     string
	signInitFlag   bool
	signVerifyFile string
	signVerifySig  string
)

var signCmd = &cobra.Command{
	Use:   "sign [file]",
	Short: "Sign files using ephemeral certificates",
	Long: `Sign files using Signet's ephemeral certificate approach.

The sign command creates CMS (PKCS#7) signatures for any file using
short-lived ephemeral certificates derived from your master key.

` + styles.Success.Render("What Works:") + `
  • File signing with CMS format
  • Ephemeral certificate generation
  • OpenSSL-compatible signatures

` + styles.Warning.Render("Planned:") + `
  • Signature verification
  • Additional output formats (JWS, raw Ed25519)
  • Batch signing operations`,
	Example: `  # Initialize Signet (one-time setup)
  signet sign --init

  # Sign a document
  signet sign document.pdf

  # Sign with custom output
  signet sign -o custom.sig data.json

  # Verify using OpenSSL
  openssl cms -verify -binary -in document.pdf.sig -inform DER -CAfile <cert>`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSign,
}

func init() {
	signCmd.Flags().BoolVar(&signInitFlag, "init", false, "Initialize Signet configuration")
	signCmd.Flags().StringVarP(&signFormat, "format", "f", "cms", "Output format: cms (more formats planned)")
	signCmd.Flags().StringVarP(&signOutput, "output", "o", "", "Output file (default: <input>.sig)")
	signCmd.Flags().StringVar(&signVerifyFile, "verify-data", "", "Data file for verification")
	signCmd.Flags().StringVar(&signVerifySig, "verify-sig", "", "Signature file for verification")

	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle initialization
	if signInitFlag {
		if err := keystore.InitializeSecure(); err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}

		// Get key ID for display
		keyID, err := keystore.GetKeyIDSecure()
		if err != nil {
			keyID = "[error reading key ID]"
		}

		fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully")
		fmt.Println(styles.Subtle.Render("  Key ID: ") + styles.Value.Render(keyID[:8]+"..."))
		fmt.Println()
		fmt.Println(styles.Info.Render("→") + " Next: " + styles.Code.Render("signet sign <file>"))
		return nil
	}

	// Handle verification (planned feature)
	if signVerifyFile != "" || signVerifySig != "" {
		fmt.Println(styles.Warning.Render("⚠") + " Verification not yet implemented")
		fmt.Println(styles.Subtle.Render("  For now, use OpenSSL:"))
		fmt.Println(styles.Code.Render("  openssl cms -verify -binary -in <sig> -inform DER -CAfile <cert>"))
		return nil
	}

	// Require file argument for signing
	if len(args) != 1 {
		return fmt.Errorf("file argument required (use --help for usage)")
	}

	inputFile := args[0]

	// Determine output file
	outputFile := signOutput
	if outputFile == "" {
		outputFile = inputFile + ".sig"
	}

	// Read input file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Load master key from OS keyring
	masterKey, err := keystore.LoadMasterKeySecure()
	// Fallback to file-based if keyring fails
	if err != nil {
		fmt.Fprintln(os.Stderr, styles.Warning.Render("⚠")+" Keyring access failed, falling back to file-based storage")
		masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			msg := styles.Info.Render("→") + " Run " + styles.Code.Render("signet sign --init") + " to initialize\n"
			fmt.Fprint(os.Stderr, msg)
			return fmt.Errorf("failed to load master key: %w", err)
		}
	}
	defer masterKey.Destroy()

	// Create Local CA
	ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)

	// Calculate certificate validity
	certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

	// Generate ephemeral certificate with secure key handling
	cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}
	defer secEphemeralKey.Destroy()

	// Extract the raw key for CMS signing
	ephemeralKey := secEphemeralKey.Key()

	// Create CMS signature based on format
	var signature []byte
	switch signFormat {
	case "cms":
		signature, err = cms.SignData(data, cert, ed25519.PrivateKey(ephemeralKey))
		if err != nil {
			return fmt.Errorf("failed to create CMS signature: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s (only 'cms' is currently supported)", signFormat)
	}

	// Write signature to file
	if err := os.WriteFile(outputFile, signature, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	// Success message
	fmt.Println(styles.Success.Render("✓") + " Signed successfully")
	fmt.Println(styles.Subtle.Render("  Input: ") + styles.Code.Render(inputFile))
	fmt.Println(styles.Subtle.Render("  Output: ") + styles.Code.Render(outputFile))
	fmt.Println(styles.Subtle.Render("  Format: ") + signFormat)

	return nil
}
