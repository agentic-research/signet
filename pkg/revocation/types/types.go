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

// GetKeys returns a defensive copy of the Keys map to prevent external modifications.
// The returned map and all byte slices are copies that can be safely modified.
func (b *CABundle) GetKeys() map[string][]byte {
	if b.Keys == nil {
		return nil
	}

	result := make(map[string][]byte, len(b.Keys))
	for k, v := range b.Keys {
		// Create a copy of each byte slice
		vcopy := make([]byte, len(v))
		copy(vcopy, v)
		result[k] = vcopy
	}
	return result
}

// SetKeys sets the Keys map with defensive copying to prevent external modifications.
// The provided map values are copied to prevent external changes affecting the bundle.
func (b *CABundle) SetKeys(keys map[string][]byte) {
	if keys == nil {
		b.Keys = nil
		return
	}

	b.Keys = make(map[string][]byte, len(keys))
	for k, v := range keys {
		// Create a copy of each byte slice
		vcopy := make([]byte, len(v))
		copy(vcopy, v)
		b.Keys[k] = vcopy
	}
}
