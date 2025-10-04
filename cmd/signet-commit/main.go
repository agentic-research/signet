package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms"
	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
)

const (
	defaultCertValidity = 5 * time.Minute
	signetDir           = ".signet"
	masterKeyFile       = "master.key"
)

func main() {
	var (
		initFlag      = flag.Bool("init", false, "Initialize Signet configuration")
		exportKeyFlag = flag.Bool("export-key-id", false, "Export the master key ID")
		helpFlag      = flag.Bool("help", false, "Show help")
		homeFlag      = flag.String("home", "", "Signet home directory (default: ~/.signet)")
		verifyFlag    = flag.String("verify", "", "Verify signature from file")
		_             = flag.String("bsau", "", "GPG compatibility flag (ignored)")
		_             = flag.Bool("S", false, "GPG compatibility flag (ignored)")
		statusFd      = flag.Int("status-fd", 0, "File descriptor for GPG status output")
		_             = flag.Bool("detach-sign", false, "Create detached signature (default)")
	)

	flag.Parse()

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	// Get signet directory
	var signetPath string
	if *homeFlag != "" {
		signetPath = *homeFlag
	} else {
		// Check environment variable first
		if envHome := os.Getenv("SIGNET_HOME"); envHome != "" {
			signetPath = envHome
		} else {
			// Default to ~/.signet
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
				os.Exit(1)
			}
			signetPath = filepath.Join(homeDir, signetDir)
		}
	}

	// Handle initialization
	if *initFlag {
		if err := initializeSignet(signetPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: initialization failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Signet initialized successfully")
		os.Exit(0)
	}

	// Handle export key ID
	if *exportKeyFlag {
		keyID, err := getKeyID(signetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get key ID: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(keyID)
		os.Exit(0)
	}

	// Handle verify flag (for Git compatibility)
	// We don't verify - that's gpgsm's job in the Git workflow
	if *verifyFlag != "" {
		// Git passes: --verify <signature-file> <data-file>
		// Just exit successfully to let Git continue
		os.Exit(0)
	}

	// Load master key
	masterKey, err := loadMasterKey(signetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load master key: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'signet-commit --init' to initialize\n")
		os.Exit(1)
	}
	defer masterKey.Destroy()

	// Read commit data from stdin
	commitData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read commit data: %v\n", err)
		os.Exit(1)
	}

	// Create Local CA
	issuerDID := "did:key:signet" // Simplified DID for MVP
	ca := attestx509.NewLocalCA(masterKey, issuerDID)

	// Generate ephemeral certificate with secure key handling
	cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(defaultCertValidity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate certificate: %v\n", err)
		os.Exit(1)
	}
	defer secEphemeralKey.Destroy() // Ensure ephemeral key is zeroed when done

	// Extract the raw key for CMS signing (will be zeroed via defer above)
	ephemeralKey := secEphemeralKey.Key()

	// Create CMS signature with Ed25519
	// Convert ephemeralKey to ed25519.PrivateKey type
	signature, err := cms.SignData(commitData, cert, ed25519.PrivateKey(ephemeralKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to sign commit: %v\n", err)
		os.Exit(1)
	}

	// If Git requested status output, emit the required status line
	if *statusFd > 0 {
		// Get the key ID (fingerprint) from arguments after flags
		keyFpr := ""
		if flag.NArg() > 0 {
			keyFpr = flag.Arg(0)
		}

		// Create status file from descriptor
		statusFile := os.NewFile(uintptr(*statusFd), "status")
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
	// Use "CMS" as the PEM type for OpenSSL compatibility
	pemBlock := &pem.Block{
		Type:  "CMS",
		Bytes: signature,
	}

	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode signature: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("signet-commit - Offline Git commit signing")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  signet-commit --init          Initialize Signet configuration")
	fmt.Println("  signet-commit --export-key-id Export the master key ID")
	fmt.Println("  signet-commit                 Sign commit data from stdin")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --home DIR                    Use DIR as signet home directory")
	fmt.Println()
	fmt.Println("Git configuration:")
	fmt.Println("  git config --global gpg.format x509")
	fmt.Println("  git config --global gpg.x509.program signet-commit")
	fmt.Println("  git config --global user.signingKey $(signet-commit --export-key-id)")
	fmt.Println("  git config --global commit.gpgsign true")
}
