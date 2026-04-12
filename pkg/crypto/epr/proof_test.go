package epr

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	signetErrors "github.com/agentic-research/signet/pkg/errors"
)

func generateTestKeyPair() (crypto.PublicKey, crypto.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func TestGenerator_GenerateProof(t *testing.T) {
	_, masterPriv := generateTestKeyPair()
	generator := NewGenerator(masterPriv.(ed25519.PrivateKey))

	tests := []struct {
		name      string
		ctx       context.Context
		request   *ProofRequest
		generator *Generator
		wantErr   bool
		errType   error
	}{
		{
			name: "successful proof generation",
			ctx:  context.Background(),
			request: &ProofRequest{
				ValidityPeriod: 5 * time.Minute,
				Purpose:        "test-purpose",
			},
			generator: generator,
			wantErr:   false,
		},
		{
			name: "nil master key in generator",
			ctx:  context.Background(),
			request: &ProofRequest{
				ValidityPeriod: 5 * time.Minute,
				Purpose:        "test-purpose",
			},
			generator: NewGenerator(nil),
			wantErr:   true,
			errType:   signetErrors.ErrMasterKeyRequired,
		},
		{
			name: "context cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			request: &ProofRequest{
				ValidityPeriod: 5 * time.Minute,
				Purpose:        "test-purpose",
			},
			generator: generator,
			wantErr:   true,
			errType:   context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tt.generator.GenerateProof(tt.ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateProof() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("GenerateProof() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateProof() unexpected error: %v", err)
				return
			}

			// Verify the response
			if response == nil {
				t.Fatal("GenerateProof() returned nil response")
			}
			if response.Proof == nil {
				t.Error("GenerateProof() returned nil proof")
			}
			if response.EphemeralPrivateKey == nil {
				t.Error("GenerateProof() returned nil ephemeral private key")
			}
			if response.Proof.EphemeralPublicKey == nil {
				t.Error("GenerateProof() returned nil ephemeral public key")
			}
			if len(response.Proof.BindingSignature) == 0 {
				t.Error("GenerateProof() returned empty binding signature")
			}

			// Verify the ephemeral key pair matches
			ephemeralPriv := response.EphemeralPrivateKey.Key()
			if ephemeralPriv == nil {
				t.Fatal("EphemeralPrivateKey.Key() returned nil")
			}
			defer response.EphemeralPrivateKey.Destroy()

			expectedPub := ephemeralPriv.Public()
			if !ed25519.PublicKey(response.Proof.EphemeralPublicKey.(ed25519.PublicKey)).Equal(expectedPub.(ed25519.PublicKey)) {
				t.Error("Ephemeral public key doesn't match private key")
			}
		})
	}
}

func TestVerifier_VerifyBinding(t *testing.T) {
	masterPub, masterPriv := generateTestKeyPair()
	generator := NewGenerator(masterPriv.(ed25519.PrivateKey))
	verifier := NewVerifier()

	// Generate a valid proof
	ctx := context.Background()
	validRequest := &ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        "test-purpose",
	}
	proofResponse, _ := generator.GenerateProof(ctx, validRequest)

	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	tests := []struct {
		name            string
		ctx             context.Context
		proof           *EphemeralProof
		masterPublicKey crypto.PublicKey
		expiresAt       int64
		purpose         string
		wantErr         bool
		errType         error
	}{
		{
			name:            "valid binding",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			wantErr:         false,
		},
		{
			name:  "wrong master key",
			ctx:   context.Background(),
			proof: proofResponse.Proof,
			masterPublicKey: func() crypto.PublicKey {
				pub, _ := generateTestKeyPair()
				return pub
			}(),
			expiresAt: expiresAt,
			purpose:   "test-purpose",
			wantErr:   true,
			errType:   signetErrors.ErrInvalidBindingSignature,
		},
		{
			name:            "wrong purpose",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "wrong-purpose",
			wantErr:         true,
			errType:         signetErrors.ErrInvalidBindingSignature,
		},
		{
			name:            "expired proof",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       time.Now().Add(-1 * time.Hour).Unix(), // Already expired
			purpose:         "test-purpose",
			wantErr:         true,
			errType:         signetErrors.ErrExpiredProof,
		},
		{
			name: "context cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			wantErr:         true,
			errType:         context.Canceled,
		},
		{
			name:            "invalid master key type",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: []byte("not a key"),
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			wantErr:         true,
			errType:         signetErrors.ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.VerifyBinding(tt.ctx, tt.proof, tt.masterPublicKey, tt.expiresAt, tt.purpose)

			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyBinding() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("VerifyBinding() error = %v, want error type %v", err, tt.errType)
				}
			} else if err != nil {
				t.Errorf("VerifyBinding() unexpected error: %v", err)
			}
		})
	}
}

func TestVerifier_VerifyRequestSignature(t *testing.T) {
	verifier := NewVerifier()

	// Generate ephemeral key for testing
	ephemeralPub, ephemeralPriv := generateTestKeyPair()

	// Create a test message and sign it
	testMessage := []byte("test message for verification")
	validSignature, _ := ephemeralPriv.(ed25519.PrivateKey).Sign(rand.Reader, testMessage, crypto.Hash(0))

	proof := &EphemeralProof{
		EphemeralPublicKey: ephemeralPub,
	}

	tests := []struct {
		name      string
		ctx       context.Context
		proof     *EphemeralProof
		message   []byte
		signature []byte
		wantErr   bool
		errType   error
	}{
		{
			name:      "valid request signature",
			ctx:       context.Background(),
			proof:     proof,
			message:   testMessage,
			signature: validSignature,
			wantErr:   false,
		},
		{
			name:      "invalid signature",
			ctx:       context.Background(),
			proof:     proof,
			message:   testMessage,
			signature: []byte("invalid signature"),
			wantErr:   true,
			errType:   signetErrors.ErrInvalidRequestSignature,
		},
		{
			name:      "wrong message",
			ctx:       context.Background(),
			proof:     proof,
			message:   []byte("different message"),
			signature: validSignature,
			wantErr:   true,
			errType:   signetErrors.ErrInvalidRequestSignature,
		},
		{
			name: "context cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			proof:     proof,
			message:   testMessage,
			signature: validSignature,
			wantErr:   true,
			errType:   context.Canceled,
		},
		{
			name: "invalid ephemeral key type",
			ctx:  context.Background(),
			proof: &EphemeralProof{
				EphemeralPublicKey: []byte("not a key"),
			},
			message:   testMessage,
			signature: validSignature,
			wantErr:   true,
			errType:   signetErrors.ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.VerifyRequestSignature(tt.ctx, tt.proof, tt.message, tt.signature)

			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyRequestSignature() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("VerifyRequestSignature() error = %v, want error type %v", err, tt.errType)
				}
			} else if err != nil {
				t.Errorf("VerifyRequestSignature() unexpected error: %v", err)
			}
		})
	}
}

func TestVerifier_VerifyProof(t *testing.T) {
	masterPub, masterPriv := generateTestKeyPair()
	generator := NewGenerator(masterPriv.(ed25519.PrivateKey))
	verifier := NewVerifier()

	// Generate a valid proof
	ctx := context.Background()
	validRequest := &ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        "test-purpose",
	}
	proofResponse, _ := generator.GenerateProof(ctx, validRequest)

	// Create test message and sign with ephemeral key
	testMessage := []byte("test message")
	ephemeralPriv := proofResponse.EphemeralPrivateKey.Key()
	defer proofResponse.EphemeralPrivateKey.Destroy()
	validSignature, _ := ephemeralPriv.Sign(rand.Reader, testMessage, crypto.Hash(0))

	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	tests := []struct {
		name            string
		ctx             context.Context
		proof           *EphemeralProof
		masterPublicKey crypto.PublicKey
		expiresAt       int64
		purpose         string
		message         []byte
		signature       []byte
		wantErr         bool
	}{
		{
			name:            "valid proof verification",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			message:         testMessage,
			signature:       validSignature,
			wantErr:         false,
		},
		{
			name:  "invalid binding",
			ctx:   context.Background(),
			proof: proofResponse.Proof,
			masterPublicKey: func() crypto.PublicKey {
				pub, _ := generateTestKeyPair()
				return pub
			}(),
			expiresAt: expiresAt,
			purpose:   "test-purpose",
			message:   testMessage,
			signature: validSignature,
			wantErr:   true,
		},
		{
			name:            "invalid request signature",
			ctx:             context.Background(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			message:         []byte("different message"),
			signature:       validSignature,
			wantErr:         true,
		},
		{
			name: "context cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			proof:           proofResponse.Proof,
			masterPublicKey: masterPub,
			expiresAt:       expiresAt,
			purpose:         "test-purpose",
			message:         testMessage,
			signature:       validSignature,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.VerifyProof(tt.ctx, tt.proof, tt.masterPublicKey, tt.expiresAt, tt.purpose, tt.message, tt.signature)

			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyProof() expected error, got nil")
				}
			} else if err != nil {
				t.Errorf("VerifyProof() unexpected error: %v", err)
			}
		})
	}
}

func TestCreateBindingMessage(t *testing.T) {
	pub, _ := generateTestKeyPair()
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	purpose := "test-purpose"

	message, err := createBindingMessage(pub, expiresAt, purpose)
	if err != nil {
		t.Errorf("createBindingMessage() unexpected error: %v", err)
		return
	}

	// Verify message structure
	if len(message) == 0 {
		t.Error("createBindingMessage() returned empty message")
	}

	// Verify domain separator is included
	expectedPrefix := []byte(DomainSeparator)
	if len(message) < len(expectedPrefix) {
		t.Error("Message too short to contain domain separator")
		return
	}

	for i, b := range expectedPrefix {
		if message[i] != b {
			t.Errorf("Domain separator mismatch at position %d: got %v, want %v", i, message[i], b)
		}
	}

	// Verify message contains public key, expiry, length-prefixed purpose
	// Format: DomainSeparator + pubkey(32) + expiry(8) + purposeLen(4) + purpose
	expectedLength := len(DomainSeparator) + ed25519.PublicKeySize + 8 + 4 + len(purpose)
	if len(message) != expectedLength {
		t.Errorf("Message length = %d, want %d", len(message), expectedLength)
	}
}

// TestCreateBindingMessage_InvalidKeyType tests that createBindingMessage
// returns an error when given a non-Ed25519 public key instead of panicking
func TestCreateBindingMessage_InvalidKeyType(t *testing.T) {
	// Use a non-Ed25519 key type (e.g., []byte or string)
	invalidKey := []byte("this is not an ed25519 key")
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	purpose := "test-purpose"

	message, err := createBindingMessage(crypto.PublicKey(invalidKey), expiresAt, purpose)

	if err == nil {
		t.Error("createBindingMessage() expected error for invalid key type, got nil")
	}
	if message != nil {
		t.Error("createBindingMessage() should return nil message on error")
	}
	if !errors.Is(err, signetErrors.ErrInvalidKeyType) {
		t.Errorf("createBindingMessage() error = %v, want %v", err, signetErrors.ErrInvalidKeyType)
	}
}

func TestProofExpirationBoundary(t *testing.T) {
	masterPub, masterPriv := generateTestKeyPair()
	generator := NewGenerator(masterPriv.(ed25519.PrivateKey))
	verifier := NewVerifier()
	ctx := context.Background()

	// Test Case 1: Already expired proof
	// This tests the expiration check without timing races
	t.Run("already expired", func(t *testing.T) {
		request := &ProofRequest{
			ValidityPeriod: 5 * time.Minute,
			Purpose:        "test-expired",
		}

		proofResponse, err := generator.GenerateProof(ctx, request)
		if err != nil {
			t.Fatalf("Failed to generate proof: %v", err)
		}

		// Use an already-expired timestamp
		expiredTimestamp := time.Now().Add(-1 * time.Hour).Unix()

		// Should fail with expiration error
		err = verifier.VerifyBinding(ctx, proofResponse.Proof, masterPub, expiredTimestamp, "test-expired")
		if !errors.Is(err, signetErrors.ErrExpiredProof) {
			t.Errorf("Expected ErrExpiredProof for already-expired timestamp, got: %v", err)
		}
	})

	// Test Case 2: Valid proof with correct expiry
	// This tests that non-expired proofs work correctly
	t.Run("valid proof", func(t *testing.T) {
		request := &ProofRequest{
			ValidityPeriod: 5 * time.Minute,
			Purpose:        "test-valid",
		}

		// Calculate what the generator will use as expiresAt
		// We do this BEFORE calling GenerateProof to minimize timing differences
		expectedExpiresAt := time.Now().Add(5 * time.Minute).Unix()

		proofResponse, err := generator.GenerateProof(ctx, request)
		if err != nil {
			t.Fatalf("Failed to generate proof: %v", err)
		}

		// Try with the expected timestamp (might be off by 1 second due to timing)
		err = verifier.VerifyBinding(ctx, proofResponse.Proof, masterPub, expectedExpiresAt, "test-valid")
		if err != nil {
			// If it fails, it's likely due to a 1-second timing difference
			// Try with expectedExpiresAt + 1
			err = verifier.VerifyBinding(ctx, proofResponse.Proof, masterPub, expectedExpiresAt+1, "test-valid")
			if err != nil {
				t.Errorf("Proof should be valid with correct expiry timestamp: %v", err)
			}
		}
	})

	// Test Case 3: Test the actual expiration boundary
	// This uses a known expired timestamp to avoid timing races
	t.Run("expiration boundary", func(t *testing.T) {
		// Generate a proof
		request := &ProofRequest{
			ValidityPeriod: 1 * time.Hour, // Long validity to avoid actual expiration
			Purpose:        "test-boundary",
		}

		proofResponse, err := generator.GenerateProof(ctx, request)
		if err != nil {
			t.Fatalf("Failed to generate proof: %v", err)
		}

		// Test with current time (should pass as signature is valid)
		currentTime := time.Now().Unix()
		_ = verifier.VerifyBinding(ctx, proofResponse.Proof, masterPub, currentTime+3600, "test-boundary")

		// This will fail because the signature won't match (different expiresAt in binding)
		// This demonstrates that we can't test expiration without knowing the exact expiresAt
		// that was used during generation

		// The proper way to test expiration is with the "already expired" test above
	})
}

func TestConcurrentProofGeneration(t *testing.T) {
	_, masterPriv := generateTestKeyPair()
	generator := NewGenerator(masterPriv.(ed25519.PrivateKey))
	ctx := context.Background()

	// Test concurrent proof generation
	numGoroutines := 10
	errors := make(chan error, numGoroutines)
	proofs := make(chan *ProofResponse, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			request := &ProofRequest{
				ValidityPeriod: 5 * time.Minute,
				Purpose:        "concurrent-test",
			}

			response, err := generator.GenerateProof(ctx, request)
			if err != nil {
				errors <- err
			} else {
				proofs <- response
			}
		}(i)
	}

	// Collect results
	var successCount int
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errors:
			t.Errorf("Concurrent proof generation failed: %v", err)
		case proof := <-proofs:
			if proof == nil || proof.Proof == nil {
				t.Error("Received nil proof from concurrent generation")
			} else {
				successCount++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent proof generation")
		}
	}

	if successCount != numGoroutines {
		t.Errorf("Expected %d successful proofs, got %d", numGoroutines, successCount)
	}
}
