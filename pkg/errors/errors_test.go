package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorVariables(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"InvalidSignature", ErrInvalidSignature, "invalid signature"},
		{"KeyNotFound", ErrKeyNotFound, "key not found"},
		{"ExpiredToken", ErrExpiredToken, "token has expired"},
		{"InvalidCertificate", ErrInvalidCertificate, "invalid certificate"},
		{"NotInitialized", ErrNotInitialized, "signet not initialized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureError(t *testing.T) {
	tests := []struct {
		name    string
		sigType string
		reason  string
		wrapped error
		want    string
	}{
		{
			name:    "WithWrappedError",
			sigType: "binding",
			reason:  "verification failed",
			wrapped: fmt.Errorf("underlying error"),
			want:    "signature error (binding): verification failed: underlying error",
		},
		{
			name:    "WithoutWrappedError",
			sigType: "request",
			reason:  "invalid format",
			wrapped: nil,
			want:    "signature error (request): invalid format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewSignatureError(tt.sigType, tt.reason, tt.wrapped)
			if got := err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
			if tt.wrapped != nil {
				if !errors.Is(err, tt.wrapped) {
					t.Errorf("errors.Is() failed to match wrapped error")
				}
			}
		})
	}
}

func TestKeyError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		keyType   string
		wrapped   error
		want      string
	}{
		{
			name:      "WithWrappedError",
			operation: "generate",
			keyType:   "ephemeral",
			wrapped:   fmt.Errorf("crypto failure"),
			want:      "key error (generate ephemeral): crypto failure",
		},
		{
			name:      "WithoutWrappedError",
			operation: "load",
			keyType:   "master",
			wrapped:   nil,
			want:      "key error (load master)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewKeyError(tt.operation, tt.keyType, tt.wrapped)
			if got := err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
			if tt.wrapped != nil {
				if !errors.Is(err, tt.wrapped) {
					t.Errorf("errors.Is() failed to match wrapped error")
				}
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		reason  string
		wrapped error
		want    string
	}{
		{
			name:    "WithValue",
			field:   "expiry",
			value:   "invalid-date",
			reason:  "not a valid timestamp",
			wrapped: nil,
			want:    "validation error: field expiry with value 'invalid-date' is invalid: not a valid timestamp",
		},
		{
			name:    "WithoutValue",
			field:   "signature",
			value:   "",
			reason:  "missing required field",
			wrapped: nil,
			want:    "validation error: field signature is invalid: missing required field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewValidationError(tt.field, tt.value, tt.reason, tt.wrapped)
			if got := err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorIs(t *testing.T) {
	// Test that wrapped errors can be checked with errors.Is
	baseErr := ErrInvalidSignature
	wrappedErr := fmt.Errorf("failed to verify: %w", baseErr)

	if !errors.Is(wrappedErr, ErrInvalidSignature) {
		t.Errorf("errors.Is() failed to match wrapped ErrInvalidSignature")
	}

	// Test custom error type wrapping
	sigErr := NewSignatureError("test", "reason", ErrInvalidSignature)
	if !errors.Is(sigErr, ErrInvalidSignature) {
		t.Errorf("errors.Is() failed to match ErrInvalidSignature in SignatureError")
	}
}
