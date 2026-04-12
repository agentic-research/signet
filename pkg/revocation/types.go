// Package revocation provides pluggable revocation checking for Signet tokens.
package revocation

import (
	"context"
	"errors"

	"github.com/agentic-research/signet/pkg/signet"
)

// ErrBundleRollback indicates a potential rollback attack.
var ErrBundleRollback = errors.New("revocation: bundle seqno decreased (rollback attack)")

// ErrBundleTooStale indicates that the CA bundle is too old to be trusted.
var ErrBundleTooStale = errors.New("revocation: bundle too old, cannot verify freshness")

// ErrStorageCorrupted indicates that the persistent storage for the sequence number is corrupted.
var ErrStorageCorrupted = errors.New("revocation: persistent storage HMAC verification failed")

// ErrInvalidBundle indicates that the CA bundle failed signature verification.
var ErrInvalidBundle = errors.New("revocation: bundle failed signature verification")

// ErrNotFound indicates that a key was not found in storage.
// This is typically returned on first request when no seqno has been stored yet.
var ErrNotFound = errors.New("revocation: key not found")

// Checker is the interface for checking if a token is revoked.
//
// Return value semantics:
//
//	(true,  nil)   — token IS revoked, reject the request
//	(false, nil)   — token is NOT revoked, allow the request
//	(false, error) — revocation status UNKNOWN due to infrastructure failure;
//	                 callers MUST treat this as "reject" (fail-closed), NOT as
//	                 "not revoked". The middleware enforces this — see signet.go.
//
// Implementations that return (false, error) on infra failures (e.g., bundle fetch
// timeout) are correct. The caller is responsible for failing closed.
type Checker interface {
	// IsRevoked checks if a token is revoked.
	IsRevoked(ctx context.Context, token *signet.Token) (bool, error)
}
