package cabundle

import (
	"context"
	"errors"
	"sync"

	"github.com/jamestexas/signet/pkg/revocation/types"
)

// ErrNotFound is returned when a key is not found in storage.
// This is typically returned on first request when no seqno has been stored yet.
var ErrNotFound = errors.New("cabundle: key not found")

// MemoryStorage is an in-memory implementation of the types.Storage interface.
type MemoryStorage struct {
	mu     sync.RWMutex
	seqnos map[string]uint64
}

// NewMemoryStorage creates a new MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		seqnos: make(map[string]uint64),
	}
}

// GetLastSeenSeqno returns the last seen sequence number for a given issuer ID.
func (s *MemoryStorage) GetLastSeenSeqno(ctx context.Context, issuerID string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seqnos[issuerID], nil
}

// SetLastSeenSeqnoIfGreater sets the last seen sequence number if it's greater than current.
func (s *MemoryStorage) SetLastSeenSeqnoIfGreater(ctx context.Context, issuerID string, seqno uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.seqnos[issuerID]
	if seqno > current {
		s.seqnos[issuerID] = seqno
	}
	// If seqno <= current, we consider it a success (idempotent no-op)
	// or should we error? The checker logic handles rollback via ErrBundleRollback earlier.
	// But this method is strictly for persisting valid updates.
	// If another thread beat us to it, we don't need to error, just not update.
	return nil
}

var _ types.Storage = (*MemoryStorage)(nil)
