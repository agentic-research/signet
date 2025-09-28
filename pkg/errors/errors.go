package errors

import (
	"errors"
	"fmt"
)

// Common error variables for the signet library.
// These allow consumers to programmatically check error types using errors.Is()
var (
	// Signature and verification errors
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrInvalidBindingSignature = errors.New("invalid binding signature")
	ErrInvalidRequestSignature = errors.New("invalid request signature")
	ErrSignatureMismatch     = errors.New("signature mismatch")

	// Key-related errors
	ErrKeyNotFound           = errors.New("key not found")
	ErrInvalidKeyType        = errors.New("invalid key type")
	ErrKeyGenerationFailed   = errors.New("key generation failed")
	ErrMasterKeyRequired     = errors.New("master key required")
	ErrInvalidPublicKey      = errors.New("invalid public key")
	ErrInvalidPrivateKey     = errors.New("invalid private key")

	// Token and expiration errors
	ErrExpiredToken          = errors.New("token has expired")
	ErrExpiredProof          = errors.New("ephemeral proof has expired")
	ErrExpiredCertificate    = errors.New("certificate has expired")
	ErrTokenNotYetValid      = errors.New("token not yet valid")

	// Certificate errors
	ErrInvalidCertificate    = errors.New("invalid certificate")
	ErrCertificateGeneration = errors.New("certificate generation failed")
	ErrNoCertificates        = errors.New("no certificates found")

	// Encoding/Decoding errors
	ErrInvalidCBOR           = errors.New("invalid CBOR encoding")
	ErrInvalidASN1           = errors.New("invalid ASN.1 encoding")
	ErrInvalidPEM            = errors.New("invalid PEM encoding")
	ErrDecodingFailed        = errors.New("decoding failed")
	ErrEncodingFailed        = errors.New("encoding failed")

	// CMS/PKCS#7 specific errors
	ErrCMSCreationFailed     = errors.New("CMS creation failed")
	ErrInvalidCMSSignature   = errors.New("invalid CMS signature")
	ErrUnsupportedAlgorithm  = errors.New("unsupported algorithm")

	// File and I/O errors
	ErrFileNotFound          = errors.New("file not found")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrReadFailed            = errors.New("read operation failed")
	ErrWriteFailed           = errors.New("write operation failed")

	// Configuration errors
	ErrNotInitialized        = errors.New("signet not initialized")
	ErrAlreadyInitialized    = errors.New("signet already initialized")
	ErrInvalidConfiguration  = errors.New("invalid configuration")

	// Context errors
	ErrContextCanceled       = errors.New("operation canceled")
	ErrTimeout               = errors.New("operation timed out")
)

// SignatureError provides detailed information about signature verification failures
type SignatureError struct {
	Type    string // Type of signature (binding, request, CMS, etc.)
	Reason  string // Human-readable reason for failure
	Wrapped error  // Underlying error
}

func (e *SignatureError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("signature error (%s): %s: %v", e.Type, e.Reason, e.Wrapped)
	}
	return fmt.Sprintf("signature error (%s): %s", e.Type, e.Reason)
}

func (e *SignatureError) Unwrap() error {
	return e.Wrapped
}

// NewSignatureError creates a new SignatureError
func NewSignatureError(sigType, reason string, wrapped error) *SignatureError {
	return &SignatureError{
		Type:    sigType,
		Reason:  reason,
		Wrapped: wrapped,
	}
}

// KeyError provides detailed information about key operation failures
type KeyError struct {
	Operation string // Operation that failed (generate, load, verify, etc.)
	KeyType   string // Type of key (master, ephemeral, etc.)
	Wrapped   error  // Underlying error
}

func (e *KeyError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("key error (%s %s): %v", e.Operation, e.KeyType, e.Wrapped)
	}
	return fmt.Sprintf("key error (%s %s)", e.Operation, e.KeyType)
}

func (e *KeyError) Unwrap() error {
	return e.Wrapped
}

// NewKeyError creates a new KeyError
func NewKeyError(operation, keyType string, wrapped error) *KeyError {
	return &KeyError{
		Operation: operation,
		KeyType:   keyType,
		Wrapped:   wrapped,
	}
}

// ValidationError represents validation failures
type ValidationError struct {
	Field   string // Field that failed validation
	Value   string // Value that was invalid (if safe to include)
	Reason  string // Why it's invalid
	Wrapped error  // Underlying error
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation error: field %s with value '%s' is invalid: %s", e.Field, e.Value, e.Reason)
	}
	return fmt.Sprintf("validation error: field %s is invalid: %s", e.Field, e.Reason)
}

func (e *ValidationError) Unwrap() error {
	return e.Wrapped
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, value, reason string, wrapped error) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Reason:  reason,
		Wrapped: wrapped,
	}
}