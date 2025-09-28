package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
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
		verifyFlag    = flag.String("verify", "", "Verify signature from file")
		_             = flag.String("bsau", "", "GPG compatibility flag (ignored)")
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

	// Handle verify flag - properly verify the signature
	if *verifyFlag != "" {
		if err := verifySignature(*verifyFlag, flag.Args(), *statusFd); err != nil {
			fmt.Fprintf(os.Stderr, "Error: verification failed: %v\n", err)
			os.Exit(1)
		}
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

// verifySignature verifies a CMS/PKCS#7 signature using the pkcs7 library
func verifySignature(sigFile string, args []string, statusFd int) error {
	// Read signature file
	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Decode PEM if necessary
	var signature []byte
	if pemBlock, _ := pem.Decode(sigData); pemBlock != nil {
		signature = pemBlock.Bytes
	} else {
		signature = sigData
	}

	// Read data file (either from args or stdin)
	var data []byte
	if len(args) > 0 && args[0] != "-" {
		data, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read data from stdin: %w", err)
		}
	}

	// Verify the signature
	err = cms.VerifySignature(signature, data)
	
	// Write GPG status output if requested
	if statusFd > 0 {
		statusFile := os.NewFile(uintptr(statusFd), "status")
		if statusFile != nil {
			if err == nil {
				// Get certificate info for GOODSIG output
				cert, _ := cms.GetSignerCertificate(signature)
				var certInfo string
				if cert != nil {
					certInfo = cert.Subject.String()
				}
				fmt.Fprintf(statusFile, "[GNUPG:] GOODSIG %s\n", certInfo)
				fmt.Fprintf(statusFile, "[GNUPG:] VALIDSIG\n")
				fmt.Fprintf(statusFile, "[GNUPG:] TRUST_ULTIMATE\n")
			} else {
				fmt.Fprintf(statusFile, "[GNUPG:] BADSIG\n")
			}
		}
	}

	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
