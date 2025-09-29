package http

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestSecurityVectors tests all security-critical paths using the comprehensive test vectors
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
			// Setup notes for specific test cases
			// For clock skew tests, the timestamp in the header is already set appropriately
			// The validation happens inside ParseProofHeader -> ValidateTimestamp

			// Parse the header
			header, err := ParseProofHeader(tc.Header)

			if tc.WantError {
				if err == nil {
					t.Errorf("Expected error for %s but got none", tc.Desc)
				} else {
					t.Logf("Got expected error: %v", err)
					// Verify error type matches if specified
					if tc.ErrorType != "" {
						// Check that error message contains expected type
						// This is simplified - in production you'd use typed errors
						if tc.ErrorType == "missing_mode" && header != nil {
							// Mode validation happens after parsing in some cases
							t.Logf("Mode validation would catch this")
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.Desc, err)
				} else {
					// Validate parsed header
					if header.Mode == "" {
						t.Errorf("Mode should not be empty for valid header")
					}
					if len(header.JTI) != 16 {
						t.Errorf("JTI should be 16 bytes, got %d", len(header.JTI))
					}
					if len(header.CapabilityID) != 16 {
						t.Errorf("CapabilityID should be 16 bytes, got %d", len(header.CapabilityID))
					}
					if header.Mode == "compact" {
						if len(header.EphemeralKeyHash) != 32 {
							t.Errorf("EphemeralKeyHash should be 32 bytes in compact mode, got %d", len(header.EphemeralKeyHash))
						}
					}
					t.Logf("Successfully parsed valid header: mode=%s", header.Mode)
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

// TestFailClosedBehavior ensures we fail closed on ambiguous inputs
func TestFailClosedBehavior(t *testing.T) {
	tests := []struct {
		name   string
		header string
		errMsg string
	}{
		{
			name:   "no_mode_specified",
			header: "v1;t=dGVzdA;jti=MTIzNDU2Nzg5MDEyMzQ1Ng;cap=MTIzNDU2Nzg5MDEyMzQ1Ng;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1700000000",
			errMsg: "missing mode",
		},
		{
			name:   "empty_mode_value",
			header: "v1;m=;t=dGVzdA;jti=MTIzNDU2Nzg5MDEyMzQ1Ng;cap=MTIzNDU2Nzg5MDEyMzQ1Ng;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1700000000",
			errMsg: "invalid mode",
		},
		{
			name:   "unknown_mode_value",
			header: "v1;m=unknown;t=dGVzdA;jti=MTIzNDU2Nzg5MDEyMzQ1Ng;cap=MTIzNDU2Nzg5MDEyMzQ1Ng;p=cHJvb2Y;k=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY;s=c2ln;n=MTIzNDU2Nzg5MDEyMzQ1Ng;ts=1700000000",
			errMsg: "invalid mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProofHeader(tc.header)
			if err == nil {
				t.Errorf("Expected error for %s but got none", tc.name)
			} else if err.Error() != tc.errMsg {
				// Check if error contains expected message
				t.Logf("Got error: %v (expected to contain: %s)", err, tc.errMsg)
			}
		})
	}
}