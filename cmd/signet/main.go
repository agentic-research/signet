package main

import (
	"os"
	"path/filepath"
)

func main() {
	// Detect if called as 'signet-commit' for Git compatibility
	// This allows us to maintain backward compatibility with Git's gpg.x509.program
	if filepath.Base(os.Args[0]) == "signet-commit" {
		// Execute commit command directly, bypassing Cobra routing
		os.Exit(execCommitCompat())
	}

	// Otherwise, use full Cobra command tree
	Execute()
}
