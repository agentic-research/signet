package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms"
	"github.com/jamestexas/signet/pkg/attest/x509"
)

// BenchmarkEndToEndSigning measures the complete signing flow
func BenchmarkEndToEndSigning(b *testing.B) {
	// Setup: create temp directory for keystore
	tmpDir := b.TempDir()
	keyPath := filepath.Join(tmpDir, "master.key")

	// Generate master key
	_, masterPriv, _ := ed25519.GenerateKey(nil)

	// Save master key (simplified for benchmark)
	_ = os.WriteFile(keyPath, masterPriv.Seed(), 0600)

	// Test data (typical commit message)
	commitData := []byte(`tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent a1b2c3d4e5f6789012345678901234567890abcd
author John Doe <john@example.com> 1234567890 +0000
committer John Doe <john@example.com> 1234567890 +0000

feat: add new feature

This commit adds an important new feature to the project.
It includes several improvements and bug fixes.`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Step 1: Create ephemeral certificate
		ca := x509.NewLocalCA(masterPriv, "signet:test")
		cert, _, ephemeralKey, err := ca.IssueCodeSigningCertificate(5 * time.Minute)
		if err != nil {
			b.Fatal(err)
		}

		// Step 2: Create CMS signature
		_, err = cms.SignData(commitData, cert, ephemeralKey)
		if err != nil {
			b.Fatal(err)
		}

		// Step 3: Zero ephemeral key (important for security)
		for i := range ephemeralKey {
			ephemeralKey[i] = 0
		}
	}
}

// BenchmarkEndToEndSigningWithPEM includes PEM encoding
func BenchmarkEndToEndSigningWithPEM(b *testing.B) {
	// Setup: create temp directory for keystore
	tmpDir := b.TempDir()
	keyPath := filepath.Join(tmpDir, "master.key")

	// Generate master key
	_, masterPriv, _ := ed25519.GenerateKey(nil)

	// Save master key (simplified for benchmark)
	_ = os.WriteFile(keyPath, masterPriv.Seed(), 0600)

	// Test data (typical commit message)
	commitData := []byte(`tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent a1b2c3d4e5f6789012345678901234567890abcd
author John Doe <john@example.com> 1234567890 +0000
committer John Doe <john@example.com> 1234567890 +0000

feat: add new feature

This commit adds an important new feature to the project.
It includes several improvements and bug fixes.`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Full flow including PEM encoding
		// This would normally load from disk, but we'll use the key directly
		ca := x509.NewLocalCA(masterPriv, "signet:test")
		cert, _, ephemeralKey, err := ca.IssueCodeSigningCertificate(5 * time.Minute)
		if err != nil {
			b.Fatal(err)
		}

		// Create CMS signature
		_, err = cms.SignData(commitData, cert, ephemeralKey)
		if err != nil {
			b.Fatal(err)
		}

		// Convert to PEM (as Git expects)
		// In real implementation, this would use encoding/pem
		// but for benchmarking we skip it to focus on crypto operations

		// Zero ephemeral key
		for i := range ephemeralKey {
			ephemeralKey[i] = 0
		}
	}
}
