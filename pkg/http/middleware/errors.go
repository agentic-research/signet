package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Standard authentication errors
var (
	// ErrMissingProof indicates the Signet-Proof header is missing
	ErrMissingProof = errors.New("missing Signet-Proof header")

	// ErrInvalidProof indicates the proof format is invalid
	ErrInvalidProof = errors.New("invalid proof format")

	// ErrTokenNotFound indicates the token doesn't exist in the store
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenNotYetValid indicates the token's NotBefore time hasn't arrived
	ErrTokenNotYetValid = errors.New("token not yet valid")

	// ErrTokenRevoked indicates the token has been revoked
	ErrTokenRevoked = errors.New("token revoked")

	// ErrClockSkew indicates the request timestamp is outside acceptable bounds
	ErrClockSkew = errors.New("clock skew detected")

	// ErrReplayDetected indicates the same nonce was used twice
	ErrReplayDetected = errors.New("replay attack detected")

	// ErrInvalidSignature indicates cryptographic verification failed
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrKeyNotFound indicates the master key couldn't be retrieved
	ErrKeyNotFound = errors.New("master key not found")

	// ErrInternalError indicates an internal server error
	ErrInternalError = errors.New("internal server error")

	// ErrPurposeMismatch indicates the token's purpose doesn't match requirements
	ErrPurposeMismatch = errors.New("token purpose mismatch")

	// ErrRequestTooLarge indicates the request exceeds maximum allowed size
	ErrRequestTooLarge = errors.New("request too large")
)

// defaultErrorHandler returns simple text errors
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status := errorToHTTPStatus(err)
	http.Error(w, err.Error(), status)
}

// DefaultErrorHandler is the default error handler for testing/direct use
var DefaultErrorHandler ErrorHandler = defaultErrorHandler

// jsonErrorHandler returns JSON-formatted error responses
func jsonErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status := errorToHTTPStatus(err)

	response := map[string]interface{}{
		"error": map[string]interface{}{
			"message": errorToMessage(err),
			"code":    errorToCode(err),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

// errorToHTTPStatus maps errors to HTTP status codes
func errorToHTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrMissingProof):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidProof):
		return http.StatusBadRequest
	case errors.Is(err, ErrTokenNotFound):
		return http.StatusUnauthorized
	case errors.Is(err, ErrTokenExpired):
		return http.StatusUnauthorized
	case errors.Is(err, ErrTokenNotYetValid):
		return http.StatusUnauthorized
	case errors.Is(err, ErrTokenRevoked):
		return http.StatusUnauthorized
	case errors.Is(err, ErrClockSkew):
		return http.StatusUnauthorized
	case errors.Is(err, ErrReplayDetected):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidSignature):
		return http.StatusUnauthorized
	case errors.Is(err, ErrKeyNotFound):
		return http.StatusInternalServerError
	case errors.Is(err, ErrInternalError):
		return http.StatusInternalServerError
	case errors.Is(err, ErrPurposeMismatch):
		return http.StatusForbidden
	case errors.Is(err, ErrRequestTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// errorToCode returns a stable error code for API responses
func errorToCode(err error) string {
	switch {
	case errors.Is(err, ErrMissingProof):
		return "MISSING_PROOF"
	case errors.Is(err, ErrInvalidProof):
		return "INVALID_PROOF"
	case errors.Is(err, ErrTokenNotFound):
		return "TOKEN_NOT_FOUND"
	case errors.Is(err, ErrTokenExpired):
		return "TOKEN_EXPIRED"
	case errors.Is(err, ErrTokenNotYetValid):
		return "TOKEN_NOT_YET_VALID"
	case errors.Is(err, ErrTokenRevoked):
		return "TOKEN_REVOKED"
	case errors.Is(err, ErrClockSkew):
		return "CLOCK_SKEW"
	case errors.Is(err, ErrReplayDetected):
		return "REPLAY_DETECTED"
	case errors.Is(err, ErrInvalidSignature):
		return "INVALID_SIGNATURE"
	case errors.Is(err, ErrKeyNotFound):
		return "KEY_NOT_FOUND"
	case errors.Is(err, ErrPurposeMismatch):
		return "PURPOSE_MISMATCH"
	case errors.Is(err, ErrRequestTooLarge):
		return "REQUEST_TOO_LARGE"
	default:
		return "INTERNAL_ERROR"
	}
}

// errorToMessage returns a user-friendly error message
func errorToMessage(err error) string {
	switch {
	case errors.Is(err, ErrMissingProof):
		return "Authentication required. Please provide a Signet-Proof header."
	case errors.Is(err, ErrInvalidProof):
		return "The provided proof format is invalid."
	case errors.Is(err, ErrTokenNotFound):
		return "The token is not recognized or has been revoked."
	case errors.Is(err, ErrTokenExpired):
		return "The token has expired. Please obtain a new token."
	case errors.Is(err, ErrTokenNotYetValid):
		return "The token is not yet valid. Please check your system time."
	case errors.Is(err, ErrTokenRevoked):
		return "The token has been revoked."
	case errors.Is(err, ErrClockSkew):
		return "Request timestamp is outside acceptable bounds. Please sync your clock."
	case errors.Is(err, ErrReplayDetected):
		return "This request has already been processed."
	case errors.Is(err, ErrInvalidSignature):
		return "The cryptographic signature could not be verified."
	case errors.Is(err, ErrKeyNotFound):
		return "Unable to verify the issuer's identity."
	case errors.Is(err, ErrPurposeMismatch):
		return "The token is not authorized for this operation."
	case errors.Is(err, ErrRequestTooLarge):
		return "The request payload exceeds the maximum allowed size."
	default:
		return "An internal error occurred. Please try again later."
	}
}
