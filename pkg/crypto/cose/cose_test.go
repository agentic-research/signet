package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEd25519SignerVerifier(t *testing.T) {
	// Generate test key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Create signer
	signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Create verifier
	verifier, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Test data
	testPayload := []byte("test message for COSE Sign1")

	// Sign the payload
	coseSign1, err := signer.Sign(testPayload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if len(coseSign1) == 0 {
		t.Fatal("COSE Sign1 message is empty")
	}

	t.Logf("COSE Sign1 length: %d bytes", len(coseSign1))

	// Verify the signature and recover payload
	recoveredPayload, err := verifier.Verify(coseSign1)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// Check payload matches
	if string(recoveredPayload) != string(testPayload) {
		t.Errorf("payload mismatch: got %q, want %q", recoveredPayload, testPayload)
	}
}

func TestEd25519SignerInvalidKey(t *testing.T) {
	// Test with invalid key size
	invalidKey := make([]byte, 32) // Should be 64

	_, err := NewEd25519Signer(invalidKey)
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestEd25519VerifierInvalidKey(t *testing.T) {
	// Test with invalid key size
	invalidKey := make([]byte, 64) // Should be 32

	_, err := NewEd25519Verifier(invalidKey)
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestSignNilPayload(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	_, err = signer.Sign(nil)
	if err == nil {
		t.Error("expected error for nil payload, got nil")
	}
}

// TestMandatoryZeroizer verifies that zeroizers are always present and functional
func TestMandatoryZeroizer(t *testing.T) {
	t.Run("Ed25519 zeroizer", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// Create a copy to verify zeroization
		privCopy := make(ed25519.PrivateKey, len(priv))
		copy(privCopy, priv)

		signer, err := NewEd25519Signer(priv)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}

		// Verify zeroizer is set (internal check)
		if signer.zeroizer == nil {
			t.Error("Ed25519 signer should have a zeroizer function")
		}

		// Destroy the signer
		signer.Destroy()

		// Verify the key was zeroized
		allZero := true
		for _, b := range priv {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			t.Error("Ed25519 private key was not properly zeroized after Destroy()")
		}
	})

	t.Run("ECDSA P-256 zeroizer", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// Store original D value for comparison
		originalD := privKey.D.Bytes()

		signer, err := NewECDSAP256Signer(privKey)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}

		// Verify zeroizer is set
		if signer.zeroizer == nil {
			t.Error("ECDSA signer should have a zeroizer function")
		}

		// Destroy the signer
		signer.Destroy()

		// Verify the private key D was zeroized (should be nil now)
		if privKey.D != nil {
			t.Error("ECDSA private key D should be nil after Destroy()")
		}

		// Verify the public key components were also zeroized
		if privKey.PublicKey.X != nil {
			t.Error("ECDSA public key X should be nil after Destroy()")
		}
		if privKey.PublicKey.Y != nil {
			t.Error("ECDSA public key Y should be nil after Destroy()")
		}
		if privKey.PublicKey.Curve != nil {
			t.Error("ECDSA curve should be nil after Destroy()")
		}

		// Verify we had a non-empty key before destruction
		if len(originalD) == 0 {
			t.Error("Original ECDSA private key D was empty")
		}
	})
}

func TestVerifyInvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	verifier, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Try to verify garbage data
	invalidCOSE := []byte("not a valid COSE message")
	_, err = verifier.Verify(invalidCOSE)
	if err == nil {
		t.Error("expected error for invalid COSE message, got nil")
	}
}

func TestVerifyNilMessage(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	verifier, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	_, err = verifier.Verify(nil)
	if err == nil {
		t.Error("expected error for nil message, got nil")
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	// Generate two different key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate first key pair: %v", err)
	}

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second key pair: %v", err)
	}

	// Sign with first key
	signer, err := NewEd25519Signer(priv1)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	coseSign1, err := signer.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Try to verify with second key (should fail)
	verifier, err := NewEd25519Verifier(pub2)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	_, err = verifier.Verify(coseSign1)
	if err == nil {
		t.Error("expected verification to fail with wrong key, got success")
	}

	// Verify with correct key (should succeed)
	verifier1, err := NewEd25519Verifier(pub1)
	if err != nil {
		t.Fatalf("failed to create verifier with correct key: %v", err)
	}

	payload, err := verifier1.Verify(coseSign1)
	if err != nil {
		t.Errorf("verification with correct key failed: %v", err)
	}
	if string(payload) != "test" {
		t.Errorf("payload mismatch: got %q, want %q", payload, "test")
	}
}

func TestNewSignerInterface(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test with EdDSA algorithm
	signer, err := NewSigner(priv, "EdDSA")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	payload := []byte("test")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature is empty")
	}

	// Test with empty algorithm (should default to EdDSA)
	signer2, err := NewSigner(priv, "")
	if err != nil {
		t.Fatalf("NewSigner with empty algorithm failed: %v", err)
	}

	sig2, err := signer2.Sign(payload)
	if err != nil {
		t.Fatalf("Sign with default algorithm failed: %v", err)
	}
	if len(sig2) == 0 {
		t.Error("signature is empty")
	}

	// Test with unsupported algorithm
	_, err = NewSigner(priv, "RS256")
	if err == nil {
		t.Error("expected error for unsupported algorithm, got nil")
	}

	// Test with wrong key type
	_, err = NewSigner("not a key", "EdDSA")
	if err == nil {
		t.Error("expected error for wrong key type, got nil")
	}
}

func TestNewVerifierInterface(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signature
	signer, _ := NewEd25519Signer(priv)
	coseSign1, _ := signer.Sign([]byte("test"))

	// Test verifier interface
	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	payload, err := verifier.Verify(coseSign1)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(payload) != "test" {
		t.Errorf("payload mismatch: got %q, want %q", payload, "test")
	}

	// Test with wrong key type
	_, err = NewVerifier("not a key")
	if err == nil {
		t.Error("expected error for wrong key type, got nil")
	}
}

func TestEmptyPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, _ := NewEd25519Signer(priv)
	verifier, _ := NewEd25519Verifier(pub)

	// Empty payload should work
	emptyPayload := []byte{}
	coseSign1, err := signer.Sign(emptyPayload)
	if err != nil {
		t.Fatalf("failed to sign empty payload: %v", err)
	}

	recovered, err := verifier.Verify(coseSign1)
	if err != nil {
		t.Fatalf("failed to verify empty payload: %v", err)
	}

	if len(recovered) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(recovered))
	}
}

func TestLargePayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, _ := NewEd25519Signer(priv)
	verifier, _ := NewEd25519Verifier(pub)

	// Test with large payload (1MB)
	largePayload := make([]byte, 1024*1024)
	rand.Read(largePayload)

	coseSign1, err := signer.Sign(largePayload)
	if err != nil {
		t.Fatalf("failed to sign large payload: %v", err)
	}

	recovered, err := verifier.Verify(coseSign1)
	if err != nil {
		t.Fatalf("failed to verify large payload: %v", err)
	}

	if len(recovered) != len(largePayload) {
		t.Errorf("payload size mismatch: got %d, want %d", len(recovered), len(largePayload))
	}

	// Just check first and last bytes to avoid full comparison of 1MB
	if recovered[0] != largePayload[0] || recovered[len(recovered)-1] != largePayload[len(largePayload)-1] {
		t.Error("payload content mismatch")
	}
}

// TestConcurrentSigners tests that multiple goroutines can use different signers concurrently
func TestConcurrentSigners(t *testing.T) {
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine gets its own key pair and signer
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Errorf("goroutine %d: failed to generate key: %v", id, err)
				return
			}

			signer, err := NewEd25519Signer(priv)
			if err != nil {
				t.Errorf("goroutine %d: failed to create signer: %v", id, err)
				return
			}
			defer signer.Destroy()

			// Sign a payload
			payload := []byte(fmt.Sprintf("message from goroutine %d", id))
			sig, err := signer.Sign(payload)
			if err != nil {
				t.Errorf("goroutine %d: failed to sign: %v", id, err)
				return
			}

			if len(sig) == 0 {
				t.Errorf("goroutine %d: signature is empty", id)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestConcurrentVerifiers tests that a single verifier can be used concurrently
func TestConcurrentVerifiers(t *testing.T) {
	// Create a signer and sign a message
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, _ := NewEd25519Signer(priv)
	defer signer.Destroy()

	payload := []byte("test message for concurrent verification")
	sig, _ := signer.Sign(payload)

	// Create a single verifier
	verifier, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Use it from multiple goroutines
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Verify the signature
			recovered, err := verifier.Verify(sig)
			if err != nil {
				t.Errorf("goroutine %d: verification failed: %v", id, err)
				return
			}

			if string(recovered) != string(payload) {
				t.Errorf("goroutine %d: payload mismatch", id)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestSignerDestroy tests that a destroyed signer cannot be used
func TestSignerDestroy(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewEd25519Signer(priv)

	// First sign should work
	_, err := signer.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// Destroy the signer
	signer.Destroy()

	// Second sign should fail with specific error
	_, err = signer.Sign([]byte("test"))
	if err == nil {
		t.Error("expected error after Destroy(), got nil")
	}
	expectedErr := "signer has been destroyed"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}

	// Multiple destroys should be safe
	signer.Destroy()
	signer.Destroy()
}

// TestConcurrentSignAndDestroy tests for race conditions between Sign() and Destroy()
// Run with: go test -race ./pkg/crypto/cose/
func TestConcurrentSignAndDestroy(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewEd25519Signer(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	done := make(chan bool, 2)
	payload := []byte("test message")

	// Goroutine 1: Keep signing
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 100; i++ {
			_, _ = signer.Sign(payload)
		}
	}()

	// Goroutine 2: Destroy the signer
	go func() {
		defer func() { done <- true }()
		signer.Destroy()
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Final destroy should be safe
	signer.Destroy()
}

// TestECDSAP256SignerVerifier tests ECDSA P-256 signing and verification
func TestECDSAP256SignerVerifier(t *testing.T) {
	// Generate P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-256 key pair: %v", err)
	}

	// Create signer
	signer, err := NewECDSAP256Signer(privKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA signer: %v", err)
	}

	// Create verifier
	verifier, err := NewECDSAP256Verifier(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA verifier: %v", err)
	}

	// Test data
	testPayload := []byte("test message for COSE Sign1 with ECDSA P-256")

	// Sign the payload
	coseSign1, err := signer.Sign(testPayload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if len(coseSign1) == 0 {
		t.Fatal("COSE Sign1 message is empty")
	}

	t.Logf("COSE Sign1 length: %d bytes", len(coseSign1))

	// Verify the signature and recover payload
	recoveredPayload, err := verifier.Verify(coseSign1)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// Check payload matches
	if string(recoveredPayload) != string(testPayload) {
		t.Errorf("payload mismatch: got %q, want %q", recoveredPayload, testPayload)
	}
}

// TestECDSAP256VerifierInvalidKey tests verifier with invalid key
func TestECDSAP256VerifierInvalidKey(t *testing.T) {
	// Test with nil key
	_, err := NewECDSAP256Verifier(nil)
	if err == nil {
		t.Error("expected error for nil public key, got nil")
	}
}

// TestECDSAP256SignerDestroy tests that a destroyed ECDSA signer cannot be used
func TestECDSAP256SignerDestroy(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := NewECDSAP256Signer(privKey)

	// First sign should work
	_, err := signer.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// Destroy the signer
	signer.Destroy()

	// Second sign should fail with specific error
	_, err = signer.Sign([]byte("test"))
	if err == nil {
		t.Error("expected error after Destroy(), got nil")
	}
	expectedErr := "signer has been destroyed"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}

	// Multiple destroys should be safe
	signer.Destroy()
	signer.Destroy()
}

// TestECDSAP256ConcurrentSignAndDestroy tests for race conditions in ECDSA signer
// Run with: go test -race ./pkg/crypto/cose/
func TestECDSAP256ConcurrentSignAndDestroy(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewECDSAP256Signer(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	done := make(chan bool, 2)
	payload := []byte("test message")

	// Goroutine 1: Keep signing
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 100; i++ {
			_, _ = signer.Sign(payload)
		}
	}()

	// Goroutine 2: Destroy the signer
	go func() {
		defer func() { done <- true }()
		signer.Destroy()
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Final destroy should be safe
	signer.Destroy()
}

// TestECDSAP256WrongCurve tests rejection of non-P-256 curves
func TestECDSAP256WrongCurve(t *testing.T) {
	// Try to create signer with P-384 key
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	_, err = NewECDSAP256Signer(p384Key)
	if err == nil {
		t.Error("Expected error for P-384 key, got nil")
	}
	if err != nil && err.Error() != "unsupported curve: P-384 (only P-256 supported)" {
		t.Errorf("Unexpected error message: %v", err)
	}

	// Try verifier with P-384 key
	_, err = NewECDSAP256Verifier(&p384Key.PublicKey)
	if err == nil {
		t.Error("Expected error for P-384 public key, got nil")
	}
}

// TestECDSAP256SignerNilKey tests rejection of nil keys
func TestECDSAP256SignerNilKey(t *testing.T) {
	_, err := NewECDSAP256Signer(nil)
	if err == nil {
		t.Error("Expected error for nil private key, got nil")
	}
}

// TestECDSAP256SignNilPayload tests rejection of nil payloads
func TestECDSAP256SignNilPayload(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := NewECDSAP256Signer(privKey)
	defer signer.Destroy()

	_, err := signer.Sign(nil)
	if err == nil {
		t.Error("expected error for nil payload, got nil")
	}
}

// TestECDSAP256VerifyWithWrongKey tests cross-key verification attack
func TestECDSAP256VerifyWithWrongKey(t *testing.T) {
	// Generate two different P-256 key pairs
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate first key pair: %v", err)
	}

	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second key pair: %v", err)
	}

	// Sign with first key
	signer, err := NewECDSAP256Signer(priv1)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	defer signer.Destroy()

	coseSign1, err := signer.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Try to verify with second key (should fail)
	verifier2, err := NewECDSAP256Verifier(&priv2.PublicKey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	_, err = verifier2.Verify(coseSign1)
	if err == nil {
		t.Error("expected verification to fail with wrong key, got success")
	}

	// Verify with correct key (should succeed)
	verifier1, err := NewECDSAP256Verifier(&priv1.PublicKey)
	if err != nil {
		t.Fatalf("failed to create verifier with correct key: %v", err)
	}

	payload, err := verifier1.Verify(coseSign1)
	if err != nil {
		t.Errorf("verification with correct key failed: %v", err)
	}
	if string(payload) != "test" {
		t.Errorf("payload mismatch: got %q, want %q", payload, "test")
	}
}

// TestECDSAP256ConcurrentSigners tests concurrent ECDSA signers
func TestECDSAP256ConcurrentSigners(t *testing.T) {
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine gets its own key pair and signer
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Errorf("goroutine %d: failed to generate key: %v", id, err)
				return
			}

			signer, err := NewECDSAP256Signer(privKey)
			if err != nil {
				t.Errorf("goroutine %d: failed to create signer: %v", id, err)
				return
			}
			defer signer.Destroy()

			// Sign a payload
			payload := []byte(fmt.Sprintf("message from goroutine %d", id))
			sig, err := signer.Sign(payload)
			if err != nil {
				t.Errorf("goroutine %d: failed to sign: %v", id, err)
				return
			}

			if len(sig) == 0 {
				t.Errorf("goroutine %d: signature is empty", id)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestMixedAlgorithmVerification tests that Ed25519 signature can't be verified with ECDSA
func TestMixedAlgorithmVerification(t *testing.T) {
	// Generate Ed25519 key and sign
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	ed25519Signer, _ := NewEd25519Signer(ed25519Priv)
	defer ed25519Signer.Destroy()

	ed25519Sig, _ := ed25519Signer.Sign([]byte("test"))

	// Try to verify with ECDSA verifier (should fail gracefully)
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaVerifier, _ := NewECDSAP256Verifier(&ecdsaPriv.PublicKey)

	_, err = ecdsaVerifier.Verify(ed25519Sig)
	if err == nil {
		t.Error("expected Ed25519 signature verification to fail with ECDSA verifier")
	}
}
