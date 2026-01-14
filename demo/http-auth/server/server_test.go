package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/signet"
)

// TestTokenRegistry_StoreAndRetrieve_Consistency verifies that the storage key
// matches the retrieval key (JTI), preventing the 401 "Token not found" bug.
//
// Bug History:
// - Storage used EphemeralKeyID as key (line 71)
// - Retrieval used JTI from proof header (line 245)
// - Result: Token stored but never found → 401 Unauthorized
//
// Fix: Both store and retrieve use JTI as the key
func TestTokenRegistry_StoreAndRetrieve_Consistency(t *testing.T) {
	// 1. Setup Registry
	registry := NewTokenRegistry()

	// 2. Create Dummy Keys
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ephemeralID := make([]byte, 32)
	rand.Read(ephemeralID)

	// 3. Create Token (JTI is generated internally)
	token, err := signet.NewToken(
		"test-issuer",
		make([]byte, 32), // Master Hash
		ephemeralID,      // Ephemeral ID
		make([]byte, 16), // Nonce
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	record := &TokenRecord{
		Token:              token,
		MasterPublicKey:    pub,
		EphemeralPublicKey: pub,
		IssuedAt:           time.Now(),
		Purpose:            "regression-test",
	}

	// 4. Store the token
	storedID := registry.Store(record)

	// 5. Verify the Stored ID matches the JTI (The Fix)
	expectedID := hex.EncodeToString(token.JTI)
	if storedID != expectedID {
		t.Errorf("Storage Key Mismatch!\nExpected (JTI): %s\nActual (Store Return): %s", expectedID, storedID)
	}

	// 6. Attempt Retrieval using the JTI (Simulating the HTTP Handler)
	retrievedRecord, exists := registry.Get(expectedID)
	if !exists {
		t.Errorf("Failed to retrieve token using JTI: %s", expectedID)
		return
	}
	if retrievedRecord == nil {
		t.Errorf("Retrieved record is nil")
		return
	}

	// 7. Verify we got the correct record back
	if retrievedRecord.Purpose != "regression-test" {
		t.Errorf("Retrieved wrong record. Expected purpose 'regression-test', got '%s'", retrievedRecord.Purpose)
	}
}

// TestTokenRegistry_JTI_vs_EphemeralKeyID_Different verifies that JTI and
// EphemeralKeyID are indeed different values, justifying the fix.
func TestTokenRegistry_JTI_vs_EphemeralKeyID_Different(t *testing.T) {
	ephemeralID := make([]byte, 32)
	rand.Read(ephemeralID)

	token, err := signet.NewToken(
		"test-issuer",
		make([]byte, 32),
		ephemeralID,
		make([]byte, 16),
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	jtiHex := hex.EncodeToString(token.JTI)
	ephemeralIDHex := hex.EncodeToString(token.EphemeralKeyID)

	if jtiHex == ephemeralIDHex {
		t.Errorf("JTI and EphemeralKeyID should be different!\nJTI: %s\nEphemeralKeyID: %s", jtiHex, ephemeralIDHex)
	}

	t.Logf("✓ Confirmed JTI (%s...) != EphemeralKeyID (%s...)", jtiHex[:16], ephemeralIDHex[:16])
}
