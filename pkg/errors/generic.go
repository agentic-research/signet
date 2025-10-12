package errors

import "fmt"

// CodeConstraint defines the constraint for error code types.
// Error codes must be integer-based (int, int32, int64, etc.).
type CodeConstraint interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// CodedError is a generic, structured error type with an error code.
// It allows for type-safe error handling based on integer-based enum codes.
//
// Type parameter T must be an integer-based error code type (e.g., StoreErrorCode).
//
// Example usage:
//
//	type StoreErrorCode int
//	const (
//		TokenNotFound StoreErrorCode = 1
//		TokenExpired  StoreErrorCode = 2
//	)
//
//	err := errors.NewCoded(TokenNotFound, "token not found", nil)
//	if errors.HasCode(err, TokenNotFound) {
//		// Handle token not found
//	}
type CodedError[T CodeConstraint] struct {
	// Code is the structured error code for programmatic handling
	Code T
	// Message is the human-readable error message
	Message string
	// Err is the underlying error (may be nil)
	Err error
}

// NewCoded creates a new structured error with the given code, message, and underlying error.
// The underlying error may be nil.
func NewCoded[T CodeConstraint](code T, message string, err error) *CodedError[T] {
	return &CodedError[T]{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// NewCodedf creates a new structured error with formatted message.
func NewCodedf[T CodeConstraint](code T, format string, args ...interface{}) *CodedError[T] {
	return &CodedError[T]{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Err:     nil,
	}
}

// WrapCoded creates a new structured error that wraps an underlying error.
func WrapCoded[T CodeConstraint](code T, message string, err error) *CodedError[T] {
	return &CodedError[T]{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Error implements the error interface.
func (e *CodedError[T]) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap implements the error unwrapping interface.
// This allows errors.Is() and errors.As() to work correctly.
func (e *CodedError[T]) Unwrap() error {
	return e.Err
}

// HasCode checks if an error is a CodedError with the given code.
// This is the primary way to check error codes in a type-safe manner.
//
// Example:
//
//	if errors.HasCode(err, TokenNotFound) {
//		// Handle token not found
//	}
func HasCode[T CodeConstraint](err error, code T) bool {
	if err == nil {
		return false
	}

	// Check if error is directly a *CodedError[T]
	if typedErr, ok := err.(*CodedError[T]); ok {
		return typedErr.Code == code
	}

	return false
}

// GetCode extracts the error code from a structured error.
// Returns the code and true if the error is a CodedError[T].
// Returns the zero value of T and false otherwise.
func GetCode[T CodeConstraint](err error) (T, bool) {
	if err == nil {
		var zero T
		return zero, false
	}

	if typedErr, ok := err.(*CodedError[T]); ok {
		return typedErr.Code, true
	}

	var zero T
	return zero, false
}
