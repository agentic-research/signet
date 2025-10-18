package signet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestCapabilityIDGeneration(t *testing.T) {
	// Test data
	issuerID := "test-issuer"
	confirmationID := make([]byte, 32)
	ephemeralKeyID := make([]byte, 32)
	nonce := make([]byte, 16)

	// Generate random test values
	rand.Read(confirmationID)
	rand.Read(ephemeralKeyID)
	rand.Read(nonce)

	// Create token
	token, err := NewToken(issuerID, confirmationID, ephemeralKeyID, nonce, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify capabilityID is 16 bytes
	if len(token.CapabilityID) != capabilityIDSize {
		t.Errorf("CapabilityID size mismatch: got %d, want %d", len(token.CapabilityID), capabilityIDSize)
	}

	// Verify capabilityID is derived correctly (SHA-256 with domain separation and length prefixing)
	h := sha256.New()
	h.Write([]byte("signet-capability-v1"))
	// Length prefix for ephemeralKeyID (32 bytes as big-endian uint32)
	h.Write([]byte{0, 0, 0, 32})
	h.Write(ephemeralKeyID)
	// Length prefix for confirmationID (32 bytes as big-endian uint32)
	h.Write([]byte{0, 0, 0, 32})
	h.Write(confirmationID)
	expectedHash := h.Sum(nil)
	expectedCapabilityID := expectedHash[:capabilityIDSize:capabilityIDSize]

	if !bytes.Equal(token.CapabilityID, expectedCapabilityID) {
		t.Error("CapabilityID not derived correctly")
	}
}

func TestCapabilityIDUniqueness(t *testing.T) {
	// Test that different ephemeralKeyIDs produce different capabilityIDs
	issuerID := "test-issuer"
	confirmationID := make([]byte, 32)
	rand.Read(confirmationID)

	// Create two tokens with different ephemeralKeyIDs
	ephemeralKeyID1 := make([]byte, 32)
	ephemeralKeyID2 := make([]byte, 32)
	rand.Read(ephemeralKeyID1)
	rand.Read(ephemeralKeyID2)

	token1, err := NewToken(issuerID, confirmationID, ephemeralKeyID1, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token1: %v", err)
	}

	token2, err := NewToken(issuerID, confirmationID, ephemeralKeyID2, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token2: %v", err)
	}

	// Verify capabilityIDs are different
	if bytes.Equal(token1.CapabilityID, token2.CapabilityID) {
		t.Error("Different ephemeralKeyIDs should produce different capabilityIDs")
	}
}

func TestCapabilityIDBinding(t *testing.T) {
	// Test that capabilityID changes if confirmationID changes
	issuerID := "test-issuer"
	ephemeralKeyID := make([]byte, 32)
	rand.Read(ephemeralKeyID)

	// Create two tokens with different confirmationIDs
	confirmationID1 := make([]byte, 32)
	confirmationID2 := make([]byte, 32)
	rand.Read(confirmationID1)
	rand.Read(confirmationID2)

	token1, err := NewToken(issuerID, confirmationID1, ephemeralKeyID, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token1: %v", err)
	}

	token2, err := NewToken(issuerID, confirmationID2, ephemeralKeyID, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token2: %v", err)
	}

	// Verify capabilityIDs are different
	if bytes.Equal(token1.CapabilityID, token2.CapabilityID) {
		t.Error("Different confirmationIDs should produce different capabilityIDs")
	}
}

func TestCapabilityIDDomainSeparation(t *testing.T) {
	// Test that domain separation prevents cross-protocol attacks
	// The capabilityID should be unique to the signet-capability-v1 context

	issuerID := "test-issuer"
	confirmationID := make([]byte, 32)
	ephemeralKeyID := make([]byte, 32)
	rand.Read(confirmationID)
	rand.Read(ephemeralKeyID)

	token, err := NewToken(issuerID, confirmationID, ephemeralKeyID, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Calculate what the hash would be WITHOUT domain separation
	h := sha256.New()
	h.Write(ephemeralKeyID)
	h.Write(confirmationID)
	wrongHash := h.Sum(nil)
	wrongCapabilityID := wrongHash[:capabilityIDSize]

	// Verify they're different (domain separation is working)
	if bytes.Equal(token.CapabilityID, wrongCapabilityID) {
		t.Error("Domain separation not working - capabilityID matches non-domain-separated hash")
	}
}

func TestCapabilityIDCapacityLimit(t *testing.T) {
	// Test that the slice capacity is properly limited
	issuerID := "test-issuer"
	confirmationID := make([]byte, 32)
	ephemeralKeyID := make([]byte, 32)
	rand.Read(confirmationID)
	rand.Read(ephemeralKeyID)

	token, err := NewToken(issuerID, confirmationID, ephemeralKeyID, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Try to extend the slice - this should panic if capacity is properly limited
	defer func() {
		// We expect no panic because capacity should be limited
		if r := recover(); r != nil {
			// This is actually good - it means capacity is limited
			return
		}
	}()

	// Get the capacity of the slice
	capabilityIDCap := cap(token.CapabilityID)

	// Capacity should equal length (properly limited)
	if capabilityIDCap != capabilityIDSize {
		t.Errorf("CapabilityID capacity not limited: cap=%d, want=%d", capabilityIDCap, capabilityIDSize)
	}
}

// TestCapabilityIDLengthPrefixing verifies that CapabilityID generation
// properly distinguishes between inputs using length prefixing to prevent
// theoretical hash collisions. While our inputs are fixed-size (32 bytes each),
// proper cryptographic practice requires explicit domain separation.
func TestCapabilityIDLengthPrefixing(t *testing.T) {
	// Even though both ephemeralKeyID and confirmationID are fixed at 32 bytes,
	// without length prefixing there's no cryptographic proof that the hash
	// function "knows" where one input ends and another begins.

	// This is a security best practice from cryptographic literature:
	// Always use unambiguous encoding when hashing multiple values.

	issuerID := "test-issuer"

	// Test that the implementation uses proper domain separation
	ephemeralKeyID := make([]byte, 32)
	confirmationID := make([]byte, 32)
	rand.Read(ephemeralKeyID)
	rand.Read(confirmationID)

	// Create token with current implementation
	token, err := NewToken(issuerID, confirmationID, ephemeralKeyID, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify implementation uses length prefixing (the secure approach)
	hExpected := sha256.New()
	hExpected.Write([]byte("signet-capability-v1"))
	// Write length of ephemeralKeyID as big-endian uint32
	hExpected.Write([]byte{0, 0, 0, 32}) // 32 bytes
	hExpected.Write(ephemeralKeyID)
	// Write length of confirmationID as big-endian uint32
	hExpected.Write([]byte{0, 0, 0, 32}) // 32 bytes
	hExpected.Write(confirmationID)
	expectedHash := hExpected.Sum(nil)[:capabilityIDSize]

	if !bytes.Equal(token.CapabilityID, expectedHash) {
		t.Errorf("Implementation doesn't use proper length prefixing")
		t.Errorf("Expected (with length prefix): %x", expectedHash)
		t.Errorf("Got: %x", token.CapabilityID)
	}

	// Verify it's different from the vulnerable version (without length prefixing)
	hVulnerable := sha256.New()
	hVulnerable.Write([]byte("signet-capability-v1"))
	hVulnerable.Write(ephemeralKeyID)
	hVulnerable.Write(confirmationID)
	vulnerableHash := hVulnerable.Sum(nil)[:capabilityIDSize]

	// These should be different (proving we're using length prefixing)
	if bytes.Equal(vulnerableHash, expectedHash) {
		t.Error("Length prefixing didn't change the hash - this shouldn't happen with random data")
	}

	// Log for verification
	t.Logf("Vulnerable (no length prefix) hash: %x", vulnerableHash)
	t.Logf("Secure (with length prefix) hash: %x", expectedHash)
	t.Logf("Token CapabilityID: %x", token.CapabilityID)
}
