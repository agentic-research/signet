package cms

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// BenchmarkCMSSignature measures the full CMS signature generation
func BenchmarkCMSSignature(b *testing.B) {
	// Setup: create keys and certificate once
	secretKeyHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	secretKey, _ := hex.DecodeString(secretKeyHex)
	privateKey := ed25519.NewKeyFromSeed(secretKey)

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Signet"},
			CommonName:   "Test Signer",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	certDER, _ := x509.CreateCertificate(nil, template, template, privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Test data
	data := []byte("This is a test commit message for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := SignData(data, cert, privateKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCMSSignatureParallel measures parallel signature generation
func BenchmarkCMSSignatureParallel(b *testing.B) {
	// Setup: create keys and certificate once
	secretKeyHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	secretKey, _ := hex.DecodeString(secretKeyHex)
	privateKey := ed25519.NewKeyFromSeed(secretKey)

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Signet"},
			CommonName:   "Test Signer",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	certDER, _ := x509.CreateCertificate(nil, template, template, privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Test data
	data := []byte("This is a test commit message for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := SignData(data, cert, privateKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSignatureOnly measures just the Ed25519 signature operation
func BenchmarkSignatureOnly(b *testing.B) {
	secretKeyHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	secretKey, _ := hex.DecodeString(secretKeyHex)
	privateKey := ed25519.NewKeyFromSeed(secretKey)

	data := []byte("This is a test commit message for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(privateKey, data)
	}
}
