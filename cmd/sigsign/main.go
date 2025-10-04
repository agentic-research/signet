package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

const (
	defaultCertValidity = 5 * time.Minute
	signetDir           = ".signet"
	masterKeyFile       = "master.key"
)

func main() {
	var (
		signCmd   = flag.NewFlagSet("sign", flag.ExitOnError)
		verifyCmd = flag.NewFlagSet("verify", flag.ExitOnError)
		initCmd   = flag.NewFlagSet("init", flag.ExitOnError)

		// Sign flags
		formatFlag = signCmd.String("format", "cms", "Output format: cms (more formats coming)")
		keyFlag    = signCmd.String("key", "", "Path to master key (default: ~/.signet/master.key)")
		outputFlag = signCmd.String("output", "", "Output file (default: <input>.sig)")

		// Verify flags (placeholders for future implementation)
		_ = verifyCmd.String("sig", "", "Path to signature file")
		_ = verifyCmd.String("data", "", "Path to original data file")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		initCmd.Parse(os.Args[2:])
		if err := initSignet(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Signet initialized successfully")

	case "sign":
		signCmd.Parse(os.Args[2:])
		if signCmd.NArg() != 1 {
			fmt.Println("Usage: sigsign sign [options] <file>")
			os.Exit(1)
		}

		inputFile := signCmd.Arg(0)
		outputFile := *outputFlag
		if outputFile == "" {
			outputFile = inputFile + ".sig"
		}

		keyPath := *keyFlag
		if keyPath == "" {
			home, _ := os.UserHomeDir()
			keyPath = filepath.Join(home, signetDir, masterKeyFile)
		}

		if err := signFile(inputFile, outputFile, keyPath, *formatFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signed %s -> %s\n", inputFile, outputFile)

	case "verify":
		verifyCmd.Parse(os.Args[2:])
		fmt.Println("Verification coming soon (use OpenSSL for now: openssl cms -verify)")

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sigsign - Universal signer using Signet

Usage:
  sigsign init                     Initialize Signet with master key
  sigsign sign <file>              Sign a file
  sigsign verify -sig <sig> -data <file>  Verify a signature

Examples:
  sigsign init
  sigsign sign document.pdf
  sigsign sign -format cms -output custom.sig data.json`)
}

func initSignet() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	signetPath := filepath.Join(home, signetDir)
	keyPath := filepath.Join(signetPath, masterKeyFile)

	// Check if already initialized
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Printf("✓ Signet already initialized\n")
		fmt.Printf("  Master key: %s\n", keyPath)
		fmt.Printf("  Status: Ready to sign\n")
		fmt.Printf("\nTo sign a file:\n  sigsign sign <file>\n")
		return nil
	}

	fmt.Printf("Initializing Signet...\n")

	// Create directory
	if err := os.MkdirAll(signetPath, 0700); err != nil {
		return fmt.Errorf("creating signet directory: %w", err)
	}
	fmt.Printf("✓ Created directory: %s\n", signetPath)

	// Generate master key
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// Save with restrictive permissions
	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv,
	})

	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return fmt.Errorf("saving key: %w", err)
	}

	// Calculate key ID (first 8 bytes of public key hex)
	keyID := fmt.Sprintf("%X", pub[:4])

	fmt.Printf("✓ Generated Ed25519 master key\n")
	fmt.Printf("  Location: %s\n", keyPath)
	fmt.Printf("  Key ID: %s...\n", keyID)
	fmt.Printf("  Permissions: 0600 (read/write owner only)\n")
	fmt.Printf("\n✅ Signet initialized successfully!\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Sign a file:     sigsign sign document.pdf\n")
	fmt.Printf("  2. Verify (OpenSSL): openssl cms -verify -binary -in document.pdf.sig -inform PEM -CAfile <cert>\n")

	return nil
}

func signFile(inputFile, outputFile, keyPath, format string) error {
	// Read the file to sign
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	// Load master key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("invalid PEM key")
	}

	// Handle both 32-byte seed and 64-byte full key formats
	var masterPriv ed25519.PrivateKey
	if len(block.Bytes) == 32 {
		// It's a seed, expand to full key
		masterPriv = ed25519.NewKeyFromSeed(block.Bytes)
	} else if len(block.Bytes) == 64 {
		// It's already a full key
		masterPriv = ed25519.PrivateKey(block.Bytes)
	} else {
		return fmt.Errorf("invalid key length: %d", len(block.Bytes))
	}

	masterKey := keys.NewEd25519Signer(masterPriv)

	// Create Local CA
	issuerDID := "did:key:signet"
	ca := attestx509.NewLocalCA(masterKey, issuerDID)

	// Generate ephemeral certificate
	cert, _, ephemeralKey, err := ca.IssueCodeSigningCertificate(defaultCertValidity)
	if err != nil {
		return fmt.Errorf("generating certificate: %w", err)
	}

	// Zero ephemeral key after use
	defer func() {
		for i := range ephemeralKey {
			ephemeralKey[i] = 0
		}
	}()

	// Sign based on format
	var signature []byte
	switch format {
	case "cms":
		signature, err = cms.SignData(data, cert, ed25519.PrivateKey(ephemeralKey))
		if err != nil {
			return fmt.Errorf("creating CMS signature: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Write signature
	if err := os.WriteFile(outputFile, signature, 0644); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}

	return nil
}
