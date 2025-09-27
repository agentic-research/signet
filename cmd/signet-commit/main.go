package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

// signet-commit is a command-line tool for signing Git commits offline
// using ephemeral X.509 certificates issued by a local CA.
// It can be configured with: git config commit.gpg.program signet-commit

func main() {
	// Parse command-line flags
	var (
		sign    = flag.Bool("S", false, "Sign the commit")
		keyPath = flag.String("key", "", "Path to master key file")
		help    = flag.Bool("h", false, "Show help")
	)
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	if !*sign {
		fmt.Fprintf(os.Stderr, "Error: -S flag is required for signing\n")
		os.Exit(1)
	}

	// Implementation will follow
	// Workflow:
	// 1. Load or generate master key
	// 2. Create LocalCA with master key
	// 3. Issue ephemeral certificate
	// 4. Sign the commit data from stdin
	// 5. Output signature in Git-compatible format
}

// printUsage prints the usage information for signet-commit
func printUsage() {
	fmt.Println("signet-commit - Offline Git commit signing with Signet")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  signet-commit -S [-key <path>]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -S              Sign the commit")
	fmt.Println("  -key <path>     Path to master key file (optional)")
	fmt.Println("  -h              Show this help message")
	fmt.Println()
	fmt.Println("Git Configuration:")
	fmt.Println("  git config commit.gpg.program signet-commit")
	fmt.Println("  git config commit.gpgsign true")
}

// loadMasterKey loads the master key from the specified path or default location
func loadMasterKey(keyPath string) (keys.Signer, error) {
	// Implementation will follow
	// If keyPath is empty, use default location (~/.signet/master.key)
	// Load Ed25519 private key from file
	// Return wrapped in Ed25519Signer
	return nil, nil
}

// signCommit signs the commit data using an ephemeral certificate
func signCommit(masterKey keys.Signer, commitData []byte) ([]byte, error) {
	// Implementation will follow
	// 1. Create LocalCA with master key
	// 2. Issue ephemeral certificate (valid for 5 minutes)
	// 3. Sign commit data with ephemeral key
	// 4. Format signature for Git
	return nil, nil
}

// formatSignatureForGit formats the signature and certificate for Git
func formatSignatureForGit(signature []byte, certificate []byte) []byte {
	// Implementation will follow
	// Format as PEM-encoded signature block that Git expects
	return nil
}