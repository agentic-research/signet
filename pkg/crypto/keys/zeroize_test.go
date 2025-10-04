package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestZeroizePrivateKey(t *testing.T) {
	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Make a copy to verify it was non-zero
	origCopy := make([]byte, len(priv))
	copy(origCopy, priv)

	// Verify the key is not already all zeros
	allZeros := make([]byte, len(priv))
	if bytes.Equal(priv, allZeros) {
		t.Fatal("Generated key should not be all zeros")
	}

	// Zero the key
	ZeroizePrivateKey(priv)

	// Verify the key is now all zeros
	if !bytes.Equal(priv, allZeros) {
		t.Error("Private key was not properly zeroed")
	}

	// Verify the original copy is still non-zero (sanity check)
	if bytes.Equal(origCopy, allZeros) {
		t.Error("Original copy should not have been affected")
	}
}

func TestZeroizeBytes(t *testing.T) {
	// Create test data
	testData := []byte("sensitive data that should be zeroed")
	origLen := len(testData)

	// Make a copy to verify it was non-zero
	origCopy := make([]byte, len(testData))
	copy(origCopy, testData)

	// Zero the data
	ZeroizeBytes(testData)

	// Verify the data is now all zeros
	allZeros := make([]byte, origLen)
	if !bytes.Equal(testData, allZeros) {
		t.Error("Bytes were not properly zeroed")
	}

	// Verify the original copy is still non-zero
	if bytes.Equal(origCopy, allZeros) {
		t.Error("Original copy should not have been affected")
	}
}

func TestSecurePrivateKey(t *testing.T) {
	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create secure wrapper
	secKey := NewSecurePrivateKey(priv)

	// Verify we can access the key
	if secKey.Key() == nil {
		t.Error("Should be able to access key before destruction")
	}

	// Verify public key access
	if secKey.Public() == nil {
		t.Error("Should be able to access public key before destruction")
	}

	// Sign a test message
	testMsg := []byte("test message")
	sig := secKey.Sign(testMsg)
	if sig == nil {
		t.Error("Should be able to sign before destruction")
	}

	// Verify the signature
	if !ed25519.Verify(secKey.Public(), testMsg, sig) {
		t.Error("Signature verification failed")
	}

	// Destroy the key
	secKey.Destroy()

	// Verify the key is no longer accessible
	if secKey.Key() != nil {
		t.Error("Key should be nil after destruction")
	}

	// Verify public key is no longer accessible
	if secKey.Public() != nil {
		t.Error("Public key should be nil after destruction")
	}

	// Verify signing no longer works
	if secKey.Sign(testMsg) != nil {
		t.Error("Sign should return nil after destruction")
	}

	// Verify the underlying key bytes are zeroed
	allZeros := make([]byte, len(priv))
	if !bytes.Equal(priv, allZeros) {
		t.Error("Underlying private key was not properly zeroed")
	}

	// Test that multiple Destroy calls are safe
	secKey.Destroy() // Should not panic
}

func TestGenerateSecureKeyPair(t *testing.T) {
	// Generate secure key pair
	pub, secPriv, err := GenerateSecureKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate secure key pair: %v", err)
	}

	// Verify public key is valid
	if pub == nil || len(pub) != ed25519.PublicKeySize {
		t.Error("Invalid public key")
	}

	// Verify private key wrapper is valid
	if secPriv == nil {
		t.Fatal("SecurePrivateKey should not be nil")
	}

	// Verify we can use the key
	testMsg := []byte("test message")
	sig := secPriv.Sign(testMsg)
	if sig == nil {
		t.Error("Should be able to sign with new key")
	}

	// Verify signature
	if !ed25519.Verify(pub, testMsg, sig) {
		t.Error("Signature verification failed")
	}

	// Clean up
	secPriv.Destroy()

	// Verify key is destroyed
	if secPriv.Key() != nil {
		t.Error("Key should be nil after destruction")
	}
}

func TestZeroizeNilSafety(t *testing.T) {
	// Test that zeroizing nil doesn't panic
	ZeroizePrivateKey(nil) // Should not panic
	ZeroizeBytes(nil)      // Should not panic

	// Test that nil SecurePrivateKey operations are safe
	var secKey *SecurePrivateKey
	if secKey.Key() != nil {
		t.Error("Nil SecurePrivateKey should return nil key")
	}
	if secKey.Public() != nil {
		t.Error("Nil SecurePrivateKey should return nil public key")
	}
	if secKey.Sign([]byte("test")) != nil {
		t.Error("Nil SecurePrivateKey should return nil signature")
	}
	secKey.Destroy() // Should not panic on nil receiver
}
