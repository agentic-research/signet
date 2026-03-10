package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentic-research/go-cms/pkg/cms"
	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	"github.com/agentic-research/signet/pkg/cli/keystore"
	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/crypto/keys"
)

var (
	// Sign subcommand flags
	signFormat       string
	signOutput       string
	signInitFlag     bool
	signForceFlag    bool
	signVerifyFile   string
	signVerifySig    string
	signSignerModule string
	signSignerOpts   string
	signAlgorithm    string
)

var signCmd = &cobra.Command{
	Use:   "sign [file]",
	Short: "Sign files using ephemeral certificates",
	Long: `Sign files using Signet's ephemeral certificate approach.

The sign command creates signatures for any file using your master key.
Ed25519 keys use CMS (PKCS#7) format with short-lived ephemeral certificates.
ML-DSA-44 keys use raw format (CMS is not yet supported for post-quantum keys).

` + styles.Success.Render("Supported Formats:") + `
  • cms  — CMS/PKCS#7 with ephemeral certificates (Ed25519)
  • raw  — Direct signature with master key (ML-DSA-44, Ed25519)

` + styles.Info.Render("Note:") + ` ML-DSA-44 keys automatically switch to raw format.

` + styles.Warning.Render("Planned:") + `
  • Signature verification
  • Additional output formats (JWS)
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
	signCmd.Flags().BoolVar(&signForceFlag, "force", false, "Force re-initialization (overwrites existing key)")
	signCmd.Flags().StringVarP(&signFormat, "format", "f", "cms", "Output format: cms, raw (ML-DSA-44 auto-switches to raw)")
	signCmd.Flags().StringVarP(&signOutput, "output", "o", "", "Output file (default: <input>.sig)")
	signCmd.Flags().StringVar(&signVerifyFile, "verify-data", "", "Data file for verification")
	signCmd.Flags().StringVar(&signVerifySig, "verify-sig", "", "Signature file for verification")
	signCmd.Flags().StringVar(&signSignerModule, "signer-module", "software", "Signer module: software (default) or pkcs11")
	signCmd.Flags().StringVar(&signSignerOpts, "signer-opts", "", "Module-specific options (e.g., for pkcs11: module-path=/path/to/lib.so,slot-id=0)")
	signCmd.Flags().StringVar(&signAlgorithm, "algorithm", "ed25519", "Signing algorithm: ed25519 (default), ml-dsa-44")

	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle initialization
	if signInitFlag {
		alg := algorithm.Algorithm(signAlgorithm)
		if !alg.Valid() {
			return fmt.Errorf("unsupported algorithm: %s (supported: ed25519, ml-dsa-44)", signAlgorithm)
		}
		if err := keystore.InitializeSecure(signForceFlag, alg); err != nil {
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
	alg, masterKey, err := keystore.LoadMasterKeySecureGeneric()
	if err != nil {
		msg := styles.Info.Render("→") + " Run " + styles.Code.Render("signet sign --init") + " to initialize\n"
		fmt.Fprint(os.Stderr, msg)
		return fmt.Errorf("failed to load master key: %w", err)
	}
	if destroyer, ok := masterKey.(interface{ Destroy() }); ok {
		defer destroyer.Destroy()
	}

	// Auto-switch to raw format for ML-DSA-44 if CMS is requested
	if alg == algorithm.MLDSA44 && signFormat == "cms" {
		fmt.Println(styles.Warning.Render("⚠") + " CMS format not supported for ML-DSA-44. Switching to 'raw' format.")
		signFormat = "raw"
	}

	// Create signature based on format
	var signature []byte
	switch signFormat {
	case "cms":
		// Create Local CA
		ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)

		// Calculate certificate validity
		certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

		// Create signer using factory (supports software and hardware backends)
		signer, err := keys.NewSigner(
			keys.WithModule(signSignerModule),
			keys.WithOptions(signSignerOpts),
			keys.WithValidity(certValidity),
		)
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}

		// Clean up signer resources if it implements Destroy()
		if destroyer, ok := signer.(interface{ Destroy() }); ok {
			defer destroyer.Destroy()
		}

		// Issue certificate for the signer (works with any crypto.Signer implementation)
		cert, _, err := ca.IssueCertificateForSigner(signer, certValidity)
		if err != nil {
			return fmt.Errorf("failed to generate certificate: %w", err)
		}

		signature, err = cms.SignDataWithSigner(data, cert, signer)
		if err != nil {
			return fmt.Errorf("failed to create CMS signature: %w", err)
		}

	case "raw":
		// For raw format with ML-DSA-44 (or others), we sign directly with the master key
		// because X.509/CMS infrastructure is not available/compatible.
		signature, err = masterKey.Sign(rand.Reader, data, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("failed to create raw signature: %w", err)
		}

	default:
		return fmt.Errorf("unsupported format: %s (only 'cms', 'raw' are currently supported)", signFormat)
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
