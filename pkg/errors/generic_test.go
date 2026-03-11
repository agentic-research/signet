package errors_test

import (
	"fmt"
	"testing"

	"github.com/agentic-research/signet/pkg/errors"
)

// Test error codes for storage operations
type StoreErrorCode int

const (
	TokenNotFound StoreErrorCode = 1
	TokenExpired  StoreErrorCode = 2
	StorageError  StoreErrorCode = 3
)

// Test error codes for validation
type ValidationCode int

const (
	InvalidInput ValidationCode = 100
	MissingField ValidationCode = 101
)

// TestCodedError_BasicUsage verifies basic creation and usage
func TestCodedError_BasicUsage(t *testing.T) {
	err := errors.NewCoded(TokenNotFound, "token not found in store", nil)

	if err.Code != TokenNotFound {
		t.Errorf("Expected code %d, got %d", TokenNotFound, err.Code)
	}

	if err.Message != "token not found in store" {
		t.Errorf("Expected message 'token not found in store', got '%s'", err.Message)
	}

	if err.Err != nil {
		t.Errorf("Expected nil underlying error, got %v", err.Err)
	}
}

// TestCodedError_ErrorMethod verifies Error() output
func TestCodedError_ErrorMethod(t *testing.T) {
	// Without underlying error
	err1 := errors.NewCoded(TokenNotFound, "token not found", nil)
	if err1.Error() != "token not found" {
		t.Errorf("Expected 'token not found', got '%s'", err1.Error())
	}

	// With underlying error
	underlying := fmt.Errorf("database connection failed")
	err2 := errors.NewCoded(StorageError, "storage error", underlying)
	expected := "storage error: database connection failed"
	if err2.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err2.Error())
	}
}

// TestCodedError_Unwrap verifies error unwrapping
func TestCodedError_Unwrap(t *testing.T) {
	underlying := fmt.Errorf("underlying error")
	err := errors.NewCoded(StorageError, "storage error", underlying)

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("Expected unwrapped error to be %v, got %v", underlying, unwrapped)
	}

	// Test with nil underlying error
	err2 := errors.NewCoded(TokenNotFound, "token not found", nil)
	if err2.Unwrap() != nil {
		t.Error("Expected Unwrap() to return nil when no underlying error")
	}
}

// TestNewCodedf verifies formatted error creation
func TestNewCodedf(t *testing.T) {
	err := errors.NewCodedf(TokenNotFound, "token %s not found in %s", "abc123", "redis")

	expected := "token abc123 not found in redis"
	if err.Message != expected {
		t.Errorf("Expected message '%s', got '%s'", expected, err.Message)
	}

	if err.Code != TokenNotFound {
		t.Errorf("Expected code %d, got %d", TokenNotFound, err.Code)
	}

	if err.Err != nil {
		t.Error("Expected nil underlying error for NewCodedf")
	}
}

// TestWrapCoded verifies error wrapping
func TestWrapCoded(t *testing.T) {
	underlying := fmt.Errorf("disk full")
	err := errors.WrapCoded(StorageError, "failed to write token", underlying)

	if err.Code != StorageError {
		t.Errorf("Expected code %d, got %d", StorageError, err.Code)
	}

	if err.Message != "failed to write token" {
		t.Errorf("Expected message 'failed to write token', got '%s'", err.Message)
	}

	if err.Err != underlying {
		t.Errorf("Expected underlying error %v, got %v", underlying, err.Err)
	}
}

// TestHasCode verifies code checking
func TestHasCode(t *testing.T) {
	err := errors.NewCoded(TokenNotFound, "token not found", nil)

	// Should match correct code
	if !errors.HasCode(err, TokenNotFound) {
		t.Error("HasCode should return true for matching code")
	}

	// Should not match different code
	if errors.HasCode(err, TokenExpired) {
		t.Error("HasCode should return false for non-matching code")
	}

	// Should return false for nil error
	if errors.HasCode(nil, TokenNotFound) {
		t.Error("HasCode should return false for nil error")
	}

	// Should return false for non-coded error
	plainErr := fmt.Errorf("plain error")
	if errors.HasCode(plainErr, TokenNotFound) {
		t.Error("HasCode should return false for plain errors")
	}
}

// TestGetCode verifies code extraction
func TestGetCode(t *testing.T) {
	err := errors.NewCoded(TokenExpired, "token expired", nil)

	code, ok := errors.GetCode[StoreErrorCode](err)
	if !ok {
		t.Fatal("GetCode should return true for CodedError")
	}
	if code != TokenExpired {
		t.Errorf("Expected code %d, got %d", TokenExpired, code)
	}

	// Test with nil error (need to provide type explicitly)
	var nilErr error
	_, ok = errors.GetCode[StoreErrorCode](nilErr)
	if ok {
		t.Error("GetCode should return false for nil error")
	}

	// Test with plain error
	plainErr := fmt.Errorf("plain error")
	_, ok = errors.GetCode[StoreErrorCode](plainErr)
	if ok {
		t.Error("GetCode should return false for plain errors")
	}
}

// TestMultipleErrorCodeTypes verifies different code types can coexist
func TestMultipleErrorCodeTypes(t *testing.T) {
	storeErr := errors.NewCoded(TokenNotFound, "token not found", nil)
	validErr := errors.NewCoded(InvalidInput, "invalid input", nil)

	// Each should match its own code
	if !errors.HasCode(storeErr, TokenNotFound) {
		t.Error("Store error should match TokenNotFound")
	}
	if !errors.HasCode(validErr, InvalidInput) {
		t.Error("Validation error should match InvalidInput")
	}

	// Store error should not match validation code
	// Note: This won't compile due to type safety, which is what we want!
	// Uncomment to verify:
	// if errors.HasCode(storeErr, InvalidInput) { ... } // Compile error
}

// TestCodedError_ErrorInterface verifies it implements error interface
func TestCodedError_ErrorInterface(t *testing.T) {
	var err error = errors.NewCoded(TokenNotFound, "not found", nil)

	if err.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

// TestCodedError_ChainedErrors verifies error chain preservation
func TestCodedError_ChainedErrors(t *testing.T) {
	// Create error chain: original -> wrapped1 -> wrapped2
	original := fmt.Errorf("original error")
	wrapped1 := errors.WrapCoded(StorageError, "storage failed", original)
	wrapped2 := errors.WrapCoded(TokenNotFound, "token not found", wrapped1)

	// Should be able to unwrap the chain
	if wrapped2.Unwrap() != wrapped1 {
		t.Error("wrapped2 should unwrap to wrapped1")
	}

	// Note: Standard library errors.Unwrap would be needed for deeper unwrapping
	// This demonstrates that CodedError properly implements Unwrap()
}

// TestCodedError_TypeSafety verifies compile-time type safety
func TestCodedError_TypeSafety(t *testing.T) {
	// These should compile:
	_ = errors.NewCoded(TokenNotFound, "message", nil)
	_ = errors.NewCoded(InvalidInput, "message", nil)

	// These would NOT compile (verify by uncommenting):
	// _ = errors.NewCoded("string code", "message", nil) // Compile error
	// _ = errors.NewCoded(3.14, "message", nil)          // Compile error
	// if errors.HasCode(storeErr, InvalidInput) {}       // Compile error (different types)
}

// TestCodedError_WithDifferentIntTypes verifies support for different integer types
func TestCodedError_WithDifferentIntTypes(t *testing.T) {
	type Code8 int8
	type Code16 int16
	type Code32 int32
	type Code64 int64
	type CodeUint uint

	const (
		Code8Value  Code8    = 1
		Code16Value Code16   = 1000
		Code32Value Code32   = 1000000
		Code64Value Code64   = 1000000000
		CodeUValue  CodeUint = 42
	)

	// All should work
	err8 := errors.NewCoded(Code8Value, "test", nil)
	err16 := errors.NewCoded(Code16Value, "test", nil)
	err32 := errors.NewCoded(Code32Value, "test", nil)
	err64 := errors.NewCoded(Code64Value, "test", nil)
	errU := errors.NewCoded(CodeUValue, "test", nil)

	if !errors.HasCode(err8, Code8Value) {
		t.Error("int8 code should match")
	}
	if !errors.HasCode(err16, Code16Value) {
		t.Error("int16 code should match")
	}
	if !errors.HasCode(err32, Code32Value) {
		t.Error("int32 code should match")
	}
	if !errors.HasCode(err64, Code64Value) {
		t.Error("int64 code should match")
	}
	if !errors.HasCode(errU, CodeUValue) {
		t.Error("uint code should match")
	}
}

// TestCodedError_RealWorldScenario simulates middleware error handling
func TestCodedError_RealWorldScenario(t *testing.T) {
	// Simulate token lookup failure
	tokenID := "abc123"
	err := errors.NewCodedf(TokenNotFound, "token %s not found", tokenID)

	// Middleware checks error code
	switch {
	case errors.HasCode(err, TokenNotFound):
		// Return 404
		t.Log("Would return HTTP 404")
	case errors.HasCode(err, TokenExpired):
		// Return 401
		t.Fatal("Should not match TokenExpired")
	case errors.HasCode(err, StorageError):
		// Return 500
		t.Fatal("Should not match StorageError")
	default:
		t.Fatal("Should match TokenNotFound")
	}
}
