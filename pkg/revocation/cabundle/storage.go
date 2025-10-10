package cabundle

import (
	"context"

	"sync"

	"github.com/jamestexas/signet/pkg/revocation/types"
)

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

// SetLastSeenSeqno sets the last seen sequence number for a given issuer ID.
func (s *MemoryStorage) SetLastSeenSeqno(ctx context.Context, issuerID string, seqno uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqnos[issuerID] = seqno
	return nil
}

var _ types.Storage = (*MemoryStorage)(nil)
