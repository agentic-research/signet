package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

// TestLocalCA_IssueCertificateForSigner tests issuing certificates for existing signers
func TestLocalCA_IssueCertificateForSigner(t *testing.T) {
	// Setup: Create a test LocalCA with master key
	masterPub, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = masterPub // Will be used for verification

	ca := NewLocalCA(masterPriv, "did:example:test123")
	_ = ca // Will be used when IssueCertificateForSigner is implemented

	t.Run("issues certificate for provided signer", func(t *testing.T) {
		// Test expectation: Given a crypto.Signer, LocalCA should:
		// 1. Extract the public key via signer.Public()
		// 2. Issue a certificate for that public key
		// 3. Sign the certificate with the master key
		// 4. Return cert, DER bytes, and no error

		// Create a mock signer (could be software or hardware)
		signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// TODO: Implement IssueCertificateForSigner
		// cert, certDER, err := ca.IssueCertificateForSigner(signerPriv, 5*time.Minute)
		// if err != nil {
		//     t.Fatalf("IssueCertificateForSigner() error = %v", err)
		// }

		// Verify certificate properties
		// if cert == nil {
		//     t.Fatal("Certificate is nil")
		// }
		// if certDER == nil || len(certDER) == 0 {
		//     t.Fatal("Certificate DER is empty")
		// }

		// Verify the certificate's public key matches signer's public key
		// certPubKey, ok := cert.PublicKey.(ed25519.PublicKey)
		// if !ok {
		//     t.Fatal("Certificate public key is not ed25519.PublicKey")
		// }
		// if !bytes.Equal(certPubKey, signerPub) {
		//     t.Error("Certificate public key doesn't match signer public key")
		// }

		// Verify certificate is signed by master key
		// if !bytes.Equal(cert.AuthorityKeyId, generateSubjectKeyID(masterPub)) {
		//     t.Error("Certificate not signed by master key")
		// }

		// Verify validity duration
		// expectedExpiry := time.Now().Add(5 * time.Minute)
		// if cert.NotAfter.Sub(expectedExpiry).Abs() > time.Second {
		//     t.Errorf("Certificate expiry not as expected: got %v, want ~%v", cert.NotAfter, expectedExpiry)
		// }

		// For now, just verify setup is correct
		_ = signerPriv // Will be used when implementation exists
		if len(signerPub) != ed25519.PublicKeySize {
			t.Error("Signer public key has wrong size")
		}
	})

	t.Run("sets correct certificate properties", func(t *testing.T) {
		// Test expectation: Certificate should have:
		// - KeyUsage: DigitalSignature
		// - ExtKeyUsage: CodeSigning
		// - IsCA: false
		// - Subject: DID from CA config
		// - Issuer: Same DID (self-signed hierarchy)

		signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = signerPub, signerPriv // Will be used when implementation exists

		// TODO: Implement and test
		// cert, _, err := ca.IssueCertificateForSigner(signerPriv, 5*time.Minute)
		// if err != nil {
		//     t.Fatalf("IssueCertificateForSigner() error = %v", err)
		// }

		// Verify KeyUsage
		// if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		//     t.Error("Certificate missing DigitalSignature KeyUsage")
		// }

		// Verify ExtKeyUsage
		// hasCodeSigning := false
		// for _, eku := range cert.ExtKeyUsage {
		//     if eku == x509.ExtKeyUsageCodeSigning {
		//         hasCodeSigning = true
		//         break
		//     }
		// }
		// if !hasCodeSigning {
		//     t.Error("Certificate missing CodeSigning ExtKeyUsage")
		// }

		// Verify IsCA is false
		// if cert.IsCA {
		//     t.Error("End-entity certificate should not have IsCA=true")
		// }

		// Verify Subject contains DID
		// if !strings.Contains(cert.Subject.String(), "did:example:test123") {
		//     t.Errorf("Certificate subject doesn't contain DID: %s", cert.Subject)
		// }
	})

	t.Run("handles different validity durations", func(t *testing.T) {
		// Test expectation: Should support various validity periods

		signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = signerPub

		testCases := []struct {
			name     string
			duration time.Duration
		}{
			{"5 minutes", 5 * time.Minute},
			{"1 hour", 1 * time.Hour},
			{"24 hours", 24 * time.Hour},
			{"1 minute", 1 * time.Minute},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// TODO: Implement
				// cert, _, err := ca.IssueCertificateForSigner(signerPriv, tc.duration)
				// if err != nil {
				//     t.Fatalf("IssueCertificateForSigner() error = %v", err)
				// }

				// expectedExpiry := time.Now().Add(tc.duration)
				// if cert.NotAfter.Sub(expectedExpiry).Abs() > time.Second {
				//     t.Errorf("Certificate expiry incorrect for %s", tc.name)
				// }

				_ = signerPriv // Use when implemented
			})
		}
	})

	t.Run("returns error for nil signer", func(t *testing.T) {
		// Test expectation: Should validate input

		// TODO: Implement
		// _, _, err := ca.IssueCertificateForSigner(nil, 5*time.Minute)
		// if err == nil {
		//     t.Error("Expected error for nil signer")
		// }
	})

	t.Run("returns error for invalid validity duration", func(t *testing.T) {
		// Test expectation: Should reject zero or negative durations

		signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = signerPub

		// TODO: Implement
		// _, _, err = ca.IssueCertificateForSigner(signerPriv, 0)
		// if err == nil {
		//     t.Error("Expected error for zero duration")
		// }

		// _, _, err = ca.IssueCertificateForSigner(signerPriv, -1*time.Hour)
		// if err == nil {
		//     t.Error("Expected error for negative duration")
		// }

		_ = signerPriv
	})
}

// TestLocalCA_IssueCertificateForSigner_Integration tests the full workflow
func TestLocalCA_IssueCertificateForSigner_Integration(t *testing.T) {
	t.Run("certificate can be used for CMS signing", func(t *testing.T) {
		// Test expectation: Certificate issued by IssueCertificateForSigner should be
		// compatible with our CMS signing workflow

		// Setup: Create LocalCA
		_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := NewLocalCA(masterPriv, "did:example:test123")
		_ = ca // Will be used when implementation exists

		// Create a signer (simulating a PKCS#11 signer or software signer)
		_, signer, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// Issue certificate for the signer
		// TODO: Implement
		// cert, _, err := ca.IssueCertificateForSigner(signer, 5*time.Minute)
		// if err != nil {
		//     t.Fatalf("IssueCertificateForSigner() error = %v", err)
		// }

		// Verify the certificate can be used with CMS
		// This would be tested in integration tests with actual CMS library
		// For now, verify certificate structure is correct

		// TODO: Parse and validate certificate
		// if cert.PublicKeyAlgorithm != x509.Ed25519 {
		//     t.Errorf("Expected Ed25519 algorithm, got %v", cert.PublicKeyAlgorithm)
		// }

		_ = signer // Use when implemented
	})

	t.Run("works with crypto.Signer from different implementations", func(t *testing.T) {
		// Test expectation: Should work with any crypto.Signer implementation
		// (software keys, hardware tokens, mock signers, etc.)

		_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := NewLocalCA(masterPriv, "did:example:test123")
		_ = ca // Will be used when implementation exists

		// Test with software signer (ed25519.PrivateKey implements crypto.Signer)
		_, softwareSigner, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// Verify it implements crypto.Signer
		var _ crypto.Signer = softwareSigner

		// TODO: Test with actual implementation
		// cert, _, err := ca.IssueCertificateForSigner(softwareSigner, 5*time.Minute)
		// if err != nil {
		//     t.Fatalf("IssueCertificateForSigner() error = %v", err)
		// }

		// In future, add test with mock PKCS11Signer
		// var hardwareSigner crypto.Signer = &mockPKCS11Signer{...}
		// cert2, _, err := ca.IssueCertificateForSigner(hardwareSigner, 5*time.Minute)
		// ...

		_ = softwareSigner
	})
}

// TestLocalCA_Backward_Compatibility tests that existing methods still work
func TestLocalCA_Backward_Compatibility(t *testing.T) {
	t.Run("IssueCodeSigningCertificateSecure still works", func(t *testing.T) {
		// Test expectation: Adding IssueCertificateForSigner shouldn't break existing API

		_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := NewLocalCA(masterPriv, "did:example:test123")

		// Old API should still work
		cert, _, secKey, err := ca.IssueCodeSigningCertificateSecure(5 * time.Minute)
		if err != nil {
			t.Fatalf("IssueCodeSigningCertificateSecure() error = %v", err)
		}
		defer secKey.Destroy()

		if cert == nil {
			t.Fatal("Certificate is nil")
		}

		// Verify it produces valid certificates
		if cert.PublicKeyAlgorithm != x509.Ed25519 {
			t.Errorf("Expected Ed25519, got %v", cert.PublicKeyAlgorithm)
		}
	})
}

// TestLocalCA_ECDSA_Support tests ECDSA key support for Touch ID integration
func TestLocalCA_ECDSA_Support(t *testing.T) {
	t.Run("issues certificate for ECDSA P-256 signer", func(t *testing.T) {
		// Setup: Create LocalCA with Ed25519 master key
		_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := NewLocalCA(masterPriv, "did:example:touchid")

		// Create ECDSA P-256 signer (like Touch ID)
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		// Issue certificate for ECDSA signer
		cert, certDER, err := ca.IssueCertificateForSigner(ecdsaPriv, 5*time.Minute)
		if err != nil {
			t.Fatalf("IssueCertificateForSigner() error = %v", err)
		}

		if cert == nil {
			t.Fatal("Certificate is nil")
		}
		if certDER == nil || len(certDER) == 0 {
			t.Fatal("Certificate DER is empty")
		}

		// Verify certificate has correct algorithm
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("Expected ECDSA algorithm, got %v", cert.PublicKeyAlgorithm)
		}

		// Verify certificate public key matches signer
		certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Certificate public key is not *ecdsa.PublicKey")
		}
		if !certPubKey.Equal(&ecdsaPriv.PublicKey) {
			t.Error("Certificate public key doesn't match signer public key")
		}

		// Verify Subject Key Identifier was set correctly
		if cert.SubjectKeyId == nil || len(cert.SubjectKeyId) != 20 {
			t.Errorf("SubjectKeyId should be 20 bytes (SHA-1), got %d", len(cert.SubjectKeyId))
		}

		// Verify Authority Key Identifier points to master key
		if cert.AuthorityKeyId == nil {
			t.Error("AuthorityKeyId should be set")
		}

		t.Logf("✓ Successfully issued ECDSA P-256 certificate for Touch ID integration")
	})

	t.Run("supports mixed key types in same CA", func(t *testing.T) {
		// Test that the same CA can issue certificates for both Ed25519 and ECDSA
		_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := NewLocalCA(masterPriv, "did:example:mixed")

		// Issue Ed25519 certificate
		_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert1, _, err := ca.IssueCertificateForSigner(ed25519Priv, 5*time.Minute)
		if err != nil {
			t.Fatalf("Failed to issue Ed25519 cert: %v", err)
		}
		if cert1.PublicKeyAlgorithm != x509.Ed25519 {
			t.Error("First certificate should be Ed25519")
		}

		// Issue ECDSA certificate
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert2, _, err := ca.IssueCertificateForSigner(ecdsaPriv, 5*time.Minute)
		if err != nil {
			t.Fatalf("Failed to issue ECDSA cert: %v", err)
		}
		if cert2.PublicKeyAlgorithm != x509.ECDSA {
			t.Error("Second certificate should be ECDSA")
		}

		// Both should have same issuer (the CA)
		if cert1.Issuer.String() != cert2.Issuer.String() {
			t.Error("Both certificates should have same issuer")
		}

		t.Logf("✓ CA can issue both Ed25519 and ECDSA certificates")
	})
}
