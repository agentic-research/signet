package signet

import (
	"encoding/hex"
	"testing"
)

func TestComputeCapabilityID(t *testing.T) {
	tests := []struct {
		name      string
		tokens    []uint64
		wantError bool
	}{
		{
			name:      "empty capability list",
			tokens:    []uint64{},
			wantError: false,
		},
		{
			name:      "single token",
			tokens:    []uint64{1},
			wantError: false,
		},
		{
			name:      "multiple tokens",
			tokens:    []uint64{1, 2, 3},
			wantError: false,
		},
		{
			name:      "duplicate tokens (should deduplicate)",
			tokens:    []uint64{1, 2, 2, 3, 1},
			wantError: false,
		},
		{
			name:      "unsorted tokens (should sort)",
			tokens:    []uint64{3, 1, 2},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capID, err := ComputeCapabilityID(tt.tokens)
			if (err != nil) != tt.wantError {
				t.Errorf("ComputeCapabilityID() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError {
				if len(capID) != 16 {
					t.Errorf("ComputeCapabilityID() returned %d bytes, want 16", len(capID))
				}
				t.Logf("capID: %s", hex.EncodeToString(capID))
			}
		})
	}
}

func TestComputeCapabilityID_Deterministic(t *testing.T) {
	// Same tokens in different order should produce same hash
	tokens1 := []uint64{3, 1, 2}
	tokens2 := []uint64{1, 2, 3}
	tokens3 := []uint64{2, 3, 1}

	cap1, err := ComputeCapabilityID(tokens1)
	if err != nil {
		t.Fatalf("ComputeCapabilityID(tokens1) failed: %v", err)
	}

	cap2, err := ComputeCapabilityID(tokens2)
	if err != nil {
		t.Fatalf("ComputeCapabilityID(tokens2) failed: %v", err)
	}

	cap3, err := ComputeCapabilityID(tokens3)
	if err != nil {
		t.Fatalf("ComputeCapabilityID(tokens3) failed: %v", err)
	}

	if !bytesEqual(cap1, cap2) {
		t.Errorf("Different order produced different hashes: %x vs %x", cap1, cap2)
	}

	if !bytesEqual(cap2, cap3) {
		t.Errorf("Different order produced different hashes: %x vs %x", cap2, cap3)
	}
}

func TestComputeCapabilityID_Deduplication(t *testing.T) {
	// Duplicate tokens should be deduplicated
	tokens1 := []uint64{1, 2, 3}
	tokens2 := []uint64{1, 1, 2, 2, 3, 3, 3}

	cap1, err := ComputeCapabilityID(tokens1)
	if err != nil {
		t.Fatalf("ComputeCapabilityID(tokens1) failed: %v", err)
	}

	cap2, err := ComputeCapabilityID(tokens2)
	if err != nil {
		t.Fatalf("ComputeCapabilityID(tokens2) failed: %v", err)
	}

	if !bytesEqual(cap1, cap2) {
		t.Errorf("Duplicates not deduplicated correctly: %x vs %x", cap1, cap2)
	}
}

func TestValidateCapabilityID(t *testing.T) {
	tokens := []uint64{1, 2, 3}
	validCapID, err := ComputeCapabilityID(tokens)
	if err != nil {
		t.Fatalf("ComputeCapabilityID() failed: %v", err)
	}

	tests := []struct {
		name      string
		capID     []byte
		tokens    []uint64
		wantError bool
	}{
		{
			name:      "valid capability ID",
			capID:     validCapID,
			tokens:    tokens,
			wantError: false,
		},
		{
			name:      "invalid capability ID (wrong hash)",
			capID:     make([]byte, 16), // all zeros
			tokens:    tokens,
			wantError: true,
		},
		{
			name:      "invalid capability ID (wrong length)",
			capID:     make([]byte, 15),
			tokens:    tokens,
			wantError: true,
		},
		{
			name:      "valid with reordered tokens",
			capID:     validCapID,
			tokens:    []uint64{3, 1, 2}, // different order, same tokens
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCapabilityID(tt.capID, tt.tokens)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateCapabilityID() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
