package header

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestSecurityVectors tests all security-critical paths using comprehensive test vectors
func TestSecurityVectors(t *testing.T) {
	// Load test vectors
	data, err := os.ReadFile("testvectors_additional.json")
	if err != nil {
		t.Fatalf("Failed to load test vectors: %v", err)
	}

	var vectors struct {
		TestVectors []struct {
			Desc        string `json:"desc"`
			Header      string `json:"header"`
			WantError   bool   `json:"want_error"`
			ErrorType   string `json:"error_type,omitempty"`
			CurrentTime int64  `json:"current_time,omitempty"`
			Setup       string `json:"setup,omitempty"`
			Note        string `json:"note,omitempty"`
		} `json:"test_vectors"`
	}

	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	for _, tc := range vectors.TestVectors {
		t.Run(tc.Desc, func(t *testing.T) {
			// Reset monotonicity cache for each test to avoid interference
			ResetMonotonicCache()

			// Parse the header
			proof, err := ParseSignetProof(tc.Header)

			if tc.WantError {
				if err == nil {
					t.Errorf("Expected error for %s but got none", tc.Desc)
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.Desc, err)
				} else {
					// Validate parsed proof
					if proof.Version == "" {
						t.Errorf("Version should not be empty for valid proof")
					}
					if len(proof.JTI) != 16 {
						t.Errorf("JTI should be 16 bytes, got %d", len(proof.JTI))
					}
					if proof.Timestamp == 0 {
						t.Errorf("Timestamp should not be zero for valid proof")
					}
					if len(proof.Signature) < 64 {
						t.Errorf("Signature should be at least 64 bytes, got %d", len(proof.Signature))
					}
					if len(proof.Nonce) != 16 {
						t.Errorf("Nonce should be 16 bytes, got %d", len(proof.Nonce))
					}
					t.Logf("Successfully parsed valid proof: mode=%s", proof.Mode)
				}
			}
		})
	}
}

// TestClockSkewEnforcement verifies the 60-second ADR-002 limit
func TestClockSkewEnforcement(t *testing.T) {
	tests := []struct {
		name      string
		offset    time.Duration
		wantError bool
	}{
		{"exactly_60s_future", 60 * time.Second, false},
		{"exactly_61s_future", 61 * time.Second, true},
		{"exactly_60s_past", -60 * time.Second, false},
		{"exactly_61s_past", -61 * time.Second, true},
		{"within_30s_future", 30 * time.Second, false},
		{"within_30s_past", -30 * time.Second, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			timestamp := time.Now().Add(tc.offset).Unix()
			err := ValidateTimestamp(timestamp, 60*time.Second, 0)

			if tc.wantError && err == nil {
				t.Errorf("Expected error for %s offset but got none", tc.offset)
			} else if !tc.wantError && err != nil {
				t.Errorf("Unexpected error for %s offset: %v", tc.offset, err)
			}
		})
	}
}

// TestMonotonicTimestamps verifies strict timestamp ordering per JTI
func TestMonotonicTimestamps(t *testing.T) {
	ResetMonotonicCache()

	jti := []byte("TEST_JTI_1234567")

	// First timestamp should succeed
	err := checkMonotonic(jti, 1700000000)
	if err != nil {
		t.Errorf("First timestamp should succeed: %v", err)
	}

	// Higher timestamp should succeed
	err = checkMonotonic(jti, 1700000001)
	if err != nil {
		t.Errorf("Increasing timestamp should succeed: %v", err)
	}

	// Same timestamp should fail
	err = checkMonotonic(jti, 1700000001)
	if err == nil {
		t.Error("Same timestamp should fail monotonicity check")
	}

	// Lower timestamp should fail
	err = checkMonotonic(jti, 1700000000)
	if err == nil {
		t.Error("Decreasing timestamp should fail monotonicity check")
	}

	// Different JTI should have independent state
	differentJTI := []byte("DIFFERENT_JTI123")
	err = checkMonotonic(differentJTI, 1700000000)
	if err != nil {
		t.Errorf("Different JTI should have independent timestamp tracking: %v", err)
	}
}

// TestMonotonicConcurrentTOCTOU tests for TOCTOU race conditions
// This test validates the fix for the race where two concurrent requests
// with same JTI could both pass monotonicity if interleaved incorrectly
func TestMonotonicConcurrentTOCTOU(t *testing.T) {
	ResetMonotonicCache()

	jti := []byte("CONCURRENT_JTI16")
	const numGoroutines = 100
	const baseTimestamp = int64(1700000000)

	// Use channels to synchronize goroutines for maximum contention
	start := make(chan struct{})
	results := make(chan error, numGoroutines)

	// Launch concurrent goroutines that all try to update at the same time
	for i := 0; i < numGoroutines; i++ {
		go func(offset int64) {
			<-start // Wait for signal to start
			ts := baseTimestamp + offset
			err := checkMonotonic(jti, ts)
			results <- err
		}(int64(i))
	}

	// Release all goroutines at once to maximize contention
	close(start)

	// Collect results
	successCount := 0
	failCount := 0
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	// Due to concurrent execution, not all will succeed
	// Only the highest timestamp at any point wins
	// But we should see SOME successes (the ones that were highest when they ran)
	if successCount == 0 {
		t.Error("Expected at least some concurrent requests to succeed")
	}
	if successCount == numGoroutines {
		t.Error("Unexpected: all concurrent requests succeeded - this suggests monotonicity is not enforced")
	}

	t.Logf("Concurrent TOCTOU test: %d/%d succeeded (expected some but not all)", successCount, numGoroutines)

	// Now test that all attempts with same timestamp fail
	ResetMonotonicCache()
	// Set initial value
	_ = checkMonotonic(jti, baseTimestamp)

	// Try to violate monotonicity concurrently
	start2 := make(chan struct{})
	results2 := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			<-start2
			// All try the same timestamp (should all fail)
			err := checkMonotonic(jti, baseTimestamp)
			results2 <- err
		}()
	}

	close(start2)

	// All should fail monotonicity
	for i := 0; i < numGoroutines; i++ {
		err := <-results2
		if err == nil {
			t.Error("Expected monotonicity violation to be detected, but request succeeded")
		}
	}
}

// TestParseSignetProofEdgeCases tests additional edge cases
func TestParseSignetProofEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantError bool
		errMsg    string
	}{
		{
			name:      "header_too_large",
			header:    "v1;m=compact;" + string(make([]byte, 9000)),
			wantError: true,
			errMsg:    "header too large",
		},
		{
			name:      "invalid_base64_jti",
			header:    "v1;m=compact;jti=!!!invalid;cap=MTIzNDU2Nzg5MDEyMzQ1Ng;s=dGVzdHNpZ25hdHVyZWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1700000000",
			wantError: true,
			errMsg:    "invalid jti encoding",
		},
		{
			name:      "invalid_timestamp_format",
			header:    "v1;m=compact;jti=MTIzNDU2Nzg5MDEyMzQ1Ng;cap=MTIzNDU2Nzg5MDEyMzQ1Ng;s=dGVzdHNpZ25hdHVyZWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=notanumber",
			wantError: true,
			errMsg:    "invalid timestamp",
		},
		{
			name:      "malformed_key_value_pair",
			header:    "v1;m=compact;malformed;jti=MTIzNDU2Nzg5MDEyMzQ1Ng",
			wantError: true,
			errMsg:    "invalid part",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignetProof(tc.header)
			if tc.wantError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tc.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
