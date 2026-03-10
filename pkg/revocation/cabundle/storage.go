package cabundle

import (
	"context"
	"errors"
	"sync"

	"github.com/agentic-research/signet/pkg/revocation/types"
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
	// If seqno <= current, this is an idempotent no-op.
	// Rollback detection is handled earlier in the checker via ErrBundleRollback.
	return nil
}

var _ types.Storage = (*MemoryStorage)(nil)
