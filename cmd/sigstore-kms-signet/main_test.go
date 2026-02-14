package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/zalando/go-keyring"
)

// setupTestKeyInKeyring initializes a test key in the mock keyring
func setupTestKeyInKeyring(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	keyring.MockInit()

	// Clean up any existing test keys
	_ = keyring.Delete(keystore.ServiceName, keystore.MasterKeyItem)
	
	// Generate a test key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Store seed in keyring (the keystore stores the seed, not the full private key)
	seed := priv.Seed()
	seedHex := hex.EncodeToString(seed)
	err = keyring.Set(keystore.ServiceName, keystore.MasterKeyItem, seedHex)
	if err != nil {
		t.Fatalf("Failed to set test key in keyring: %v", err)
	}
	
	return pub, priv
}

// setupTestKeyInFile creates a test key in the file system
func setupTestKeyInFile(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	
	// Create temporary directory
	tmpDir := t.TempDir()
	signetDir := tmpDir + "/.signet"
	
	// Initialize keystore in temp directory (generates a new key)
	err := keystore.InitializeInsecure(signetDir, false)
	if err != nil {
		t.Fatalf("Failed to initialize keystore: %v", err)
	}
	
	// Load the key to get the public key
	signer, err := keystore.LoadMasterKeyInsecure(signetDir)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}
	defer signer.Destroy()
	
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Public key is not ed25519.PublicKey")
	}
	
	return tmpDir, pub
}

// TestNewSignetKMS_ValidURISchemes tests valid URI schemes
func TestNewSignetKMS_ValidURISchemes(t *testing.T) {
	expectedPub, _ := setupTestKeyInKeyring(t)
	expectedKeyID := fmt.Sprintf("%x", expectedPub)
	
	tests := []struct {
		name      string
		resourceID string
	}{
		{"default alias", "signet://default"},
		{"master alias", "signet://master"},
		{"hex key ID", "signet://" + expectedKeyID},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kms, err := NewSignetKMS(tt.resourceID)
			if err != nil {
				t.Fatalf("NewSignetKMS failed: %v", err)
			}
			defer kms.Destroy()
			
			if kms.signer == nil {
				t.Error("Expected non-nil signer")
			}
			if kms.pubKey == nil {
				t.Error("Expected non-nil public key")
			}
			
			// Verify public key matches
			actualPub, ok := kms.pubKey.(ed25519.PublicKey)
			if !ok {
				t.Fatal("Public key is not ed25519.PublicKey")
			}
			if !bytes.Equal(actualPub, expectedPub) {
				t.Error("Public key mismatch")
			}
		})
	}
}

// TestNewSignetKMS_InvalidURIScheme tests invalid URI schemes
func TestNewSignetKMS_InvalidURIScheme(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		wantErr    string
	}{
		{"wrong scheme", "wrong://default", "invalid scheme"},
		{"no scheme", "default", "invalid scheme"},
		{"http scheme", "http://default", "invalid scheme"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kms, err := NewSignetKMS(tt.resourceID)
			if err == nil {
				if kms != nil {
					kms.Destroy()
				}
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestNewSignetKMS_EmptyKeyID tests empty key ID
func TestNewSignetKMS_EmptyKeyID(t *testing.T) {
	kms, err := NewSignetKMS("signet://")
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected error for empty key ID, got nil")
	}
	if !strings.Contains(err.Error(), "empty key ID") {
		t.Errorf("Expected error containing 'empty key ID', got %q", err.Error())
	}
}

// TestNewSignetKMS_InvalidKeyIDFormat tests invalid key ID format
func TestNewSignetKMS_InvalidKeyIDFormat(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantErr   string
	}{
		{"invalid hex", "signet://not-valid-hex-xyz", "invalid key ID format"},
		{"special chars", "signet://key-with-dashes!", "invalid key ID format"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kms, err := NewSignetKMS(tt.keyID)
			if err == nil {
				if kms != nil {
					kms.Destroy()
				}
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// TestNewSignetKMS_KeyLoadingFromSecureKeyring tests loading from secure keyring
func TestNewSignetKMS_KeyLoadingFromSecureKeyring(t *testing.T) {
	expectedPub, _ := setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	actualPub, ok := kms.pubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key is not ed25519.PublicKey")
	}
	if !bytes.Equal(actualPub, expectedPub) {
		t.Error("Public key mismatch")
	}
}

// TestNewSignetKMS_FallbackToInsecure tests fallback to file-based storage
func TestNewSignetKMS_FallbackToInsecure(t *testing.T) {
	// Ensure keyring is not available (will naturally fail for non-existent key)
	keyring.MockInit()
	_ = keyring.Delete(keystore.ServiceName, keystore.MasterKeyItem)
	
	// Setup file-based key
	tmpDir, expectedPub := setupTestKeyInFile(t)
	
	// Set HOME to temp directory so keystore looks there
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS with file fallback failed: %v", err)
	}
	defer kms.Destroy()
	
	actualPub, ok := kms.pubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key is not ed25519.PublicKey")
	}
	if !bytes.Equal(actualPub, expectedPub) {
		t.Error("Public key mismatch")
	}
}

// TestNewSignetKMS_KeyIDMismatch tests key ID verification
func TestNewSignetKMS_KeyIDMismatch(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	// Try to load with a different key ID
	wrongKeyID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	kms, err := NewSignetKMS("signet://" + wrongKeyID)
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected key ID mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Errorf("Expected error containing 'key ID mismatch', got %q", err.Error())
	}
}

// TestSignetKMS_PublicKey tests the PublicKey method
func TestSignetKMS_PublicKey(t *testing.T) {
	expectedPub, _ := setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	pub, err := kms.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}
	
	actualPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key is not ed25519.PublicKey")
	}
	if !bytes.Equal(actualPub, expectedPub) {
		t.Error("Public key mismatch")
	}
}

// TestSignetKMS_SignMessage tests the SignMessage method
func TestSignetKMS_SignMessage(t *testing.T) {
	expectedPub, _ := setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// Test successful signing
	message := []byte("test message")
	signature, err := kms.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("SignMessage() failed: %v", err)
	}
	
	// Verify signature
	if !ed25519.Verify(expectedPub, message, signature) {
		t.Error("Signature verification failed")
	}
	
	// Verify signature length
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
	}
}

// TestSignetKMS_SignMessage_SizeLimit tests message size limit
func TestSignetKMS_SignMessage_SizeLimit(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// Test with message just at the limit
	limitMessage := make([]byte, maxSignMessageSize)
	_, err = kms.SignMessage(bytes.NewReader(limitMessage))
	if err != nil {
		t.Errorf("SignMessage() should succeed at size limit, got error: %v", err)
	}
	
	// Test with message over the limit
	oversizedMessage := make([]byte, maxSignMessageSize+1)
	_, err = kms.SignMessage(bytes.NewReader(oversizedMessage))
	if err == nil {
		t.Fatal("Expected error for oversized message, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Expected error containing 'too large', got %q", err.Error())
	}
}

// TestSignetKMS_VerifySignature tests the VerifySignature method
func TestSignetKMS_VerifySignature(t *testing.T) {
	_, expectedPriv := setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// Create a valid signature
	message := []byte("test message for verification")
	signature := ed25519.Sign(expectedPriv, message)
	
	// Test successful verification
	err = kms.VerifySignature(bytes.NewReader(signature), bytes.NewReader(message))
	if err != nil {
		t.Fatalf("VerifySignature() failed: %v", err)
	}
}

// TestSignetKMS_VerifySignature_Invalid tests invalid signature verification
func TestSignetKMS_VerifySignature_Invalid(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// Create an invalid signature (wrong message)
	message := []byte("original message")
	wrongMessage := []byte("tampered message")
	
	// Sign the original message
	signature, _ := kms.SignMessage(bytes.NewReader(message))
	
	// Verify with wrong message (should fail)
	err = kms.VerifySignature(bytes.NewReader(signature), bytes.NewReader(wrongMessage))
	if err == nil {
		t.Fatal("Expected verification to fail with wrong message, got nil error")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("Expected error containing 'invalid signature', got %q", err.Error())
	}
}

// TestSignetKMS_Destroy tests the Destroy method
func TestSignetKMS_Destroy(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	
	// Should not panic
	kms.Destroy()
	
	// Destroy should be idempotent
	kms.Destroy()
}

// TestSignetKMS_DefaultAlgorithm tests the DefaultAlgorithm method
func TestSignetKMS_DefaultAlgorithm(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	algo := kms.DefaultAlgorithm()
	if algo != "ed25519" {
		t.Errorf("Expected default algorithm 'ed25519', got %q", algo)
	}
}

// TestSignetKMS_SupportedAlgorithms tests the SupportedAlgorithms method
func TestSignetKMS_SupportedAlgorithms(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	algos := kms.SupportedAlgorithms()
	if len(algos) != 1 {
		t.Errorf("Expected 1 supported algorithm, got %d", len(algos))
	}
	if algos[0] != "ed25519" {
		t.Errorf("Expected supported algorithm 'ed25519', got %q", algos[0])
	}
}

// TestSignetKMS_CreateKey tests the CreateKey method
func TestSignetKMS_CreateKey(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// CreateKey should return an error (not supported)
	_, err = kms.CreateKey(nil, "ed25519")
	if err == nil {
		t.Fatal("Expected CreateKey to return error, got nil")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("Expected error containing 'not supported', got %q", err.Error())
	}
}

// TestSignetKMS_CryptoSigner tests the CryptoSigner method
func TestSignetKMS_CryptoSigner(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	signer, opts, err := kms.CryptoSigner(nil, nil)
	if err != nil {
		t.Fatalf("CryptoSigner() failed: %v", err)
	}
	
	if signer == nil {
		t.Error("Expected non-nil signer")
	}
	
	// For Ed25519, opts should be crypto.Hash(0)
	if opts != nil {
		if hash, ok := opts.(crypto.Hash); !ok || hash != crypto.Hash(0) {
			t.Errorf("Expected crypto.Hash(0), got %v", opts)
		}
	}
	
	// Verify signer works
	message := []byte("test")
	signature, err := signer.Sign(nil, message, opts)
	if err != nil {
		t.Fatalf("Signer.Sign() failed: %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
	}
}

// TestSignetKMS_SignMessage_ReadError tests error handling during message reading
func TestSignetKMS_SignMessage_ReadError(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	// Create a reader that returns an error
	errorReader := &errorReader{err: io.ErrUnexpectedEOF}
	_, err = kms.SignMessage(errorReader)
	if err == nil {
		t.Fatal("Expected error from errorReader, got nil")
	}
}

// TestSignetKMS_VerifySignature_ReadError tests error handling during signature/message reading
func TestSignetKMS_VerifySignature_ReadError(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	kms, err := NewSignetKMS("signet://default")
	if err != nil {
		t.Fatalf("NewSignetKMS failed: %v", err)
	}
	defer kms.Destroy()
	
	errorReader := &errorReader{err: io.ErrUnexpectedEOF}
	validMessage := bytes.NewReader([]byte("test"))
	
	// Test error reading signature
	err = kms.VerifySignature(errorReader, validMessage)
	if err == nil {
		t.Fatal("Expected error reading signature, got nil")
	}
	
	// Test error reading message
	validSignature := bytes.NewReader(make([]byte, ed25519.SignatureSize))
	err = kms.VerifySignature(validSignature, errorReader)
	if err == nil {
		t.Fatal("Expected error reading message, got nil")
	}
}

// TestSignetKMS_NoKeyAvailable tests behavior when no key is available
func TestSignetKMS_NoKeyAvailable(t *testing.T) {
	// Ensure no key is available
	keyring.MockInit()
	_ = keyring.Delete(keystore.ServiceName, keystore.MasterKeyItem)
	
	// Create a temporary directory with no key file
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	
	kms, err := NewSignetKMS("signet://default")
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected error when no key available, got nil")
	}
}

// errorReader is a helper type that always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// TestNewSignetKMS_KeyIDComparison verifies key ID comparison logic
// Note: This test verifies functional correctness, not constant-time properties
func TestNewSignetKMS_KeyIDComparison(t *testing.T) {
	// This test verifies that the key ID comparison logic works correctly
	// We can't directly test timing properties in a unit test

	expectedPub, _ := setupTestKeyInKeyring(t)
	expectedKeyID := fmt.Sprintf("%x", expectedPub)
	
	// Test with correct key ID (should succeed)
	kms, err := NewSignetKMS("signet://" + expectedKeyID)
	if err != nil {
		t.Fatalf("NewSignetKMS with correct key ID failed: %v", err)
	}
	kms.Destroy()
	
	// Test with incorrect key ID of same length (should fail)
	wrongKeyID := strings.Repeat("0", len(expectedKeyID))
	kms, err = NewSignetKMS("signet://" + wrongKeyID)
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected error with wrong key ID, got nil")
	}
	
	// Test with incorrect key ID of different length (should fail)
	shortKeyID := "0123"
	kms, err = NewSignetKMS("signet://" + shortKeyID)
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected error with short key ID, got nil")
	}
}

// TestNewSignetKMS_KeyIDTruncation tests that key IDs are truncated in error messages
func TestNewSignetKMS_KeyIDTruncation(t *testing.T) {
	setupTestKeyInKeyring(t)
	
	// Use a long hex key ID that will be truncated
	longKeyID := strings.Repeat("0123456789abcdef", 8) // 128 characters
	kms, err := NewSignetKMS("signet://" + longKeyID)
	if err == nil {
		if kms != nil {
			kms.Destroy()
		}
		t.Fatal("Expected key ID mismatch error, got nil")
	}
	
	// Error message should contain truncated key IDs (16 chars + "...")
	if !strings.Contains(err.Error(), "...") {
		t.Errorf("Expected error message to contain truncated key ID with '...', got %q", err.Error())
	}
}
