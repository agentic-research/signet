package x509

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// BenchmarkCertificateGeneration measures ephemeral certificate creation
func BenchmarkCertificateGeneration(b *testing.B) {
	// Create a master key
	_, masterPriv, _ := ed25519.GenerateKey(nil)

	ca := NewLocalCA(masterPriv, "did:key:signet-bench")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, err := ca.IssueCodeSigningCertificate(5 * time.Minute)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEphemeralKeyGeneration measures just key generation
func BenchmarkEphemeralKeyGeneration(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}