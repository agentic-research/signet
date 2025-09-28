package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cms"
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
		_             = flag.String("bsau", "", "GPG compatibility flag (ignored)")
		_             = flag.Int("status-fd", 0, "GPG compatibility flag (ignored)")
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
	ca := x509.NewLocalCA(masterKey, issuerDID)

	// Generate ephemeral certificate
	cert, _, ephemeralKey, err := ca.IssueCodeSigningCertificate(defaultCertValidity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate certificate: %v\n", err)
		os.Exit(1)
	}

	// Zero ephemeral key after signing
	defer func() {
		for i := range ephemeralKey {
			ephemeralKey[i] = 0
		}
	}()

	// Create CMS signature
	signature, err := cms.SignData(commitData, cert, ephemeralKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to sign commit: %v\n", err)
		os.Exit(1)
	}

	// Output PEM-encoded signature to stdout
	pemBlock := &pem.Block{
		Type:  "SIGNED MESSAGE",
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
