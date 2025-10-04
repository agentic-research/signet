package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cms"
)

// execCommitCompat provides backward compatibility when invoked as 'signet-commit'
// This function mimics the original signet-commit behavior exactly
func execCommitCompat() int {
	// Create a new FlagSet to avoid conflicts with Cobra
	fs := flag.NewFlagSet("signet-commit", flag.ExitOnError)

	var (
		initFlag      = fs.Bool("init", false, "Initialize Signet configuration")
		exportKeyFlag = fs.Bool("export-key-id", false, "Export the master key ID")
		helpFlag      = fs.Bool("help", false, "Show help")
		homeFlag      = fs.String("home", "", "Signet home directory (default: ~/.signet)")
		verifyFlag    = fs.String("verify", "", "Verify signature from file")
		_             = fs.String("bsau", "", "GPG compatibility flag (ignored)")
		_             = fs.Bool("S", false, "GPG compatibility flag (ignored)")
		statusFd      = fs.Int("status-fd", 0, "File descriptor for GPG status output")
		_             = fs.Bool("detach-sign", false, "Create detached signature (default)")
	)

	fs.Parse(os.Args[1:])

	if *helpFlag {
		printCompatHelp()
		return 0
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Override with home flag if provided
	if *homeFlag != "" {
		cfg.Home = *homeFlag
		cfg.KeyPath = cfg.Home + "/" + keystore.MasterKeyFile
	}

	// Handle initialization
	if *initFlag {
		if err := keystore.Initialize(cfg.Home); err != nil {
			fmt.Fprintf(os.Stderr, "Error: initialization failed: %v\n", err)
			return 1
		}
		fmt.Println("Signet initialized successfully")
		return 0
	}

	// Handle export key ID
	if *exportKeyFlag {
		keyID, err := keystore.GetKeyID(cfg.KeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get key ID: %v\n", err)
			return 1
		}
		fmt.Println(keyID)
		return 0
	}

	// Handle verify flag (for Git compatibility)
	if *verifyFlag != "" {
		return 0
	}

	// Load master key
	masterKey, err := keystore.LoadMasterKey(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load master key: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'signet-commit --init' to initialize\n")
		return 1
	}
	defer masterKey.Destroy()

	// Read commit data from stdin
	commitData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read commit data: %v\n", err)
		return 1
	}

	// Create Local CA
	ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)

	// Calculate certificate validity
	certValidity := time.Duration(cfg.CertificateValidityMinutes) * time.Minute

	// Generate ephemeral certificate with secure key handling
	cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate certificate: %v\n", err)
		return 1
	}
	defer secEphemeralKey.Destroy()

	// Extract the raw key for CMS signing
	ephemeralKey := secEphemeralKey.Key()

	// Create CMS signature with Ed25519
	signature, err := cms.SignData(commitData, cert, ed25519.PrivateKey(ephemeralKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to sign commit: %v\n", err)
		return 1
	}

	// If Git requested status output, emit the required status line
	if *statusFd > 0 {
		keyFpr := ""
		if fs.NArg() > 0 {
			keyFpr = fs.Arg(0)
		}

		statusFile := os.NewFile(uintptr(*statusFd), "status")
		if statusFile != nil {
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
		fmt.Fprintf(os.Stderr, "Error: failed to encode signature: %v\n", err)
		return 1
	}

	return 0
}

func printCompatHelp() {
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
