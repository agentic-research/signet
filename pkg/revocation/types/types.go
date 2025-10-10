package types

import (
	"context"
)

// CABundle represents a collection of trusted CA public keys for a specific epoch.
type CABundle struct {
	// Epoch is the major epoch number for this bundle.
	Epoch uint64 `json:"epoch"`

	// Seqno is the sequence number for this bundle, used to prevent rollback attacks.
	Seqno uint64 `json:"seqno"`

	// Keys is a map of key IDs to public keys.
	Keys map[string][]byte `json:"keys"`

	// KeyID is the current primary key identifier (for quick checks)
	KeyID string `json:"keyId,omitempty"`

	// PrevKeyID is the previous key identifier (for grace period during rotation)
	PrevKeyID string `json:"prevKeyId,omitempty"`

	// IssuedAt is the Unix timestamp when this bundle was issued.
	// Used to detect stale bundles that might have been cached or backed up.
	IssuedAt int64 `json:"issuedAt,omitempty"`

	// Signature is a signature of the bundle, used to verify its authenticity.
	Signature []byte `json:"signature"`
}

// Fetcher is the interface for fetching a CA bundle.
type Fetcher interface {
	// Fetch fetches the CA bundle for a given issuer ID.
	Fetch(ctx context.Context, issuerID string) (*CABundle, error)
}

// Storage is the interface for persistently storing the last seen sequence number.
type Storage interface {
	// GetLastSeenSeqno returns the last seen sequence number for a given issuer ID.
	GetLastSeenSeqno(ctx context.Context, issuerID string) (uint64, error)

	// SetLastSeenSeqno sets the last seen sequence number for a given issuer ID.
	SetLastSeenSeqno(ctx context.Context, issuerID string, seqno uint64) error
}
