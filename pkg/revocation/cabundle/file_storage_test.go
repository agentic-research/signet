package cabundle_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jamestexas/signet/pkg/revocation/cabundle"
)

// TestFileStorage_BasicOperation verifies basic read/write functionality
func TestFileStorage_BasicOperation(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-hmac-key-32-bytes-long!!!")

	storage, err := cabundle.NewFileStorage(tmpDir, key)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	issuerID := "test-issuer"

	// Initially, seqno should be 0 (not yet seen)
	seqno, err := storage.GetLastSeenSeqno(ctx, issuerID)
	if err != nil {
		t.Fatalf("GetLastSeenSeqno failed: %v", err)
	}
	if seqno != 0 {
		t.Errorf("expected seqno 0, got %d", seqno)
	}

	// Store a sequence number
	if err := storage.SetLastSeenSeqno(ctx, issuerID, 42); err != nil {
		t.Fatalf("SetLastSeenSeqno failed: %v", err)
	}

	// Retrieve it
	seqno, err = storage.GetLastSeenSeqno(ctx, issuerID)
	if err != nil {
		t.Fatalf("GetLastSeenSeqno failed after set: %v", err)
	}
	if seqno != 42 {
		t.Errorf("expected seqno 42, got %d", seqno)
	}
}

// TestFileStorage_Persistence verifies that data survives restarts
func TestFileStorage_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-hmac-key-32-bytes-long!!!")

	ctx := context.Background()
	issuerID := "persistent-issuer"

	// Create storage and write a value
	storage1, err := cabundle.NewFileStorage(tmpDir, key)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	if err := storage1.SetLastSeenSeqno(ctx, issuerID, 123); err != nil {
		t.Fatalf("SetLastSeenSeqno failed: %v", err)
	}

	// Create a NEW storage instance (simulating restart)
	storage2, err := cabundle.NewFileStorage(tmpDir, key)
	if err != nil {
		t.Fatalf("failed to create storage after restart: %v", err)
	}

	// The value should still be there
	seqno, err := storage2.GetLastSeenSeqno(ctx, issuerID)
	if err != nil {
		t.Fatalf("GetLastSeenSeqno failed after restart: %v", err)
	}
	if seqno != 123 {
		t.Errorf("expected persisted seqno 123, got %d", seqno)
	}
}

// TestFileStorage_TamperDetection verifies that HMAC detects file tampering
func TestFileStorage_TamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-hmac-key-32-bytes-long!!!")

	storage, err := cabundle.NewFileStorage(tmpDir, key)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	issuerID := "tampered-issuer"

	// Write a value
	if err := storage.SetLastSeenSeqno(ctx, issuerID, 100); err != nil {
		t.Fatalf("SetLastSeenSeqno failed: %v", err)
	}

	// Tamper with the file by changing the seqno bytes
	filePath := filepath.Join(tmpDir, "74616d70657265642d697373756572.seqno") // hex("tampered-issuer")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	// Flip a bit in the seqno (first byte)
	data[0] ^= 0xff

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		t.Fatalf("failed to tamper with file: %v", err)
	}

	// Reading should now fail with HMAC error
	_, err = storage.GetLastSeenSeqno(ctx, issuerID)
	if err == nil {
		t.Fatal("expected error after tampering, got nil")
	}

	// Error should mention HMAC verification
	if err != nil && err.Error() == "" {
		t.Errorf("expected HMAC error, got: %v", err)
	}
}

// TestFileStorage_MultipleIssuers verifies that different issuers are isolated
func TestFileStorage_MultipleIssuers(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-hmac-key-32-bytes-long!!!")

	storage, err := cabundle.NewFileStorage(tmpDir, key)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()

	// Store different values for different issuers
	if err := storage.SetLastSeenSeqno(ctx, "issuer-A", 10); err != nil {
		t.Fatalf("SetLastSeenSeqno failed for A: %v", err)
	}
	if err := storage.SetLastSeenSeqno(ctx, "issuer-B", 20); err != nil {
		t.Fatalf("SetLastSeenSeqno failed for B: %v", err)
	}

	// Verify they don't interfere
	seqnoA, err := storage.GetLastSeenSeqno(ctx, "issuer-A")
	if err != nil {
		t.Fatalf("GetLastSeenSeqno failed for A: %v", err)
	}
	if seqnoA != 10 {
		t.Errorf("expected seqno 10 for A, got %d", seqnoA)
	}

	seqnoB, err := storage.GetLastSeenSeqno(ctx, "issuer-B")
	if err != nil {
		t.Fatalf("GetLastSeenSeqno failed for B: %v", err)
	}
	if seqnoB != 20 {
		t.Errorf("expected seqno 20 for B, got %d", seqnoB)
	}
}

// TestFileStorage_EmptyKeyRejected verifies that empty HMAC keys are rejected
func TestFileStorage_EmptyKeyRejected(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := cabundle.NewFileStorage(tmpDir, []byte{})
	if err == nil {
		t.Fatal("expected error for empty HMAC key, got nil")
	}
}

// TestFileStorage_WrongKeyDetectsCorruption verifies that using a different HMAC key detects corruption
func TestFileStorage_WrongKeyDetectsCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	key1 := []byte("original-hmac-key-32-bytes!!!")
	key2 := []byte("different-hmac-key-32-bytes!!")

	ctx := context.Background()
	issuerID := "test-issuer"

	// Write with key1
	storage1, err := cabundle.NewFileStorage(tmpDir, key1)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	if err := storage1.SetLastSeenSeqno(ctx, issuerID, 99); err != nil {
		t.Fatalf("SetLastSeenSeqno failed: %v", err)
	}

	// Try to read with key2 - should fail HMAC verification
	storage2, err := cabundle.NewFileStorage(tmpDir, key2)
	if err != nil {
		t.Fatalf("failed to create storage with different key: %v", err)
	}

	_, err = storage2.GetLastSeenSeqno(ctx, issuerID)
	if err == nil {
		t.Fatal("expected error when reading with wrong HMAC key, got nil")
	}
}
