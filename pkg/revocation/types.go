// Package revocation provides pluggable revocation checking for Signet tokens.
package revocation

import (
	"context"
	"errors"

	"github.com/jamestexas/signet/pkg/signet"
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
type Checker interface {
	// IsRevoked checks if a token is revoked.
	IsRevoked(ctx context.Context, token *signet.Token) (bool, error)
}
