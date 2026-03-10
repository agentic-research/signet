package cabundle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/agentic-research/signet/pkg/revocation/types"
)

var (
	// ErrStorageCorrupted indicates that the persistent storage HMAC verification failed
	ErrStorageCorrupted = errors.New("storage: HMAC verification failed (file may be corrupted or tampered)")
)

// FileStorage is a persistent, tamper-evident storage for sequence numbers.
// It uses HMAC-SHA256 to detect tampering and prevent rollback attacks.
//
// File format (per issuer):
//
//	[8 bytes: seqno (big-endian uint64)]
//	[32 bytes: HMAC-SHA256(seqno || issuerID)]
//
// Security properties:
//   - Detects tampering: HMAC verification fails if seqno is modified
//   - Prevents rollback: Attacker cannot rewind seqno without breaking HMAC
//   - Offline-first: No network required for verification
//
// Thread-safe: Uses mutex for concurrent access
type FileStorage struct {
	mu  sync.RWMutex
	dir string // Directory to store sequence files
	key []byte // HMAC key (32 bytes recommended)
}

// NewFileStorage creates a new HMAC-protected file storage.
// The directory will be created if it doesn't exist.
// The HMAC key should be 32 bytes for SHA-256, and must be kept secret.
func NewFileStorage(dir string, hmacKey []byte) (*FileStorage, error) {
	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("HMAC key cannot be empty")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &FileStorage{
		dir: dir,
		key: hmacKey,
	}, nil
}

// readSeqnoInternal reads and verifies the sequence number without locking.
// Caller must hold the lock (RLock or Lock).
func (s *FileStorage) readSeqnoInternal(issuerID string) (uint64, error) {
	filePath := s.seqnoPath(issuerID)

	// If file doesn't exist, this is the first time we're seeing this issuer
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return 0, nil
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read seqno file: %w", err)
	}

	// File format: [8 bytes seqno][32 bytes HMAC]
	if len(data) != 8+32 {
		return 0, fmt.Errorf("%w: invalid file size %d (expected %d)", ErrStorageCorrupted, len(data), 8+32)
	}

	seqnoBytes := data[:8]
	storedMAC := data[8:]

	// Verify HMAC
	expectedMAC := s.computeHMAC(seqnoBytes, issuerID)
	if !hmac.Equal(storedMAC, expectedMAC) {
		return 0, fmt.Errorf("%w: HMAC verification failed for issuer %s", ErrStorageCorrupted, issuerID)
	}

	seqno := binary.BigEndian.Uint64(seqnoBytes)
	return seqno, nil
}

// GetLastSeenSeqno returns the last seen sequence number for a given issuer ID.
// Returns 0 if no sequence number has been stored yet (first time seeing this issuer).
func (s *FileStorage) GetLastSeenSeqno(ctx context.Context, issuerID string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readSeqnoInternal(issuerID)
}

// SetLastSeenSeqnoIfGreater stores the last seen sequence number for a given issuer ID
// ONLY if the new sequence number is greater than the currently stored one.
// The seqno is protected with an HMAC to prevent tampering.
func (s *FileStorage) SetLastSeenSeqnoIfGreater(ctx context.Context, issuerID string, seqno uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read current value to ensure monotonicity
	current, err := s.readSeqnoInternal(issuerID)
	if err != nil {
		return err
	}

	// Atomic check: only update if new seqno is greater
	if seqno <= current {
		return nil // Already seen a higher or equal seqno
	}

	filePath := s.seqnoPath(issuerID)

	// Encode seqno as big-endian uint64
	seqnoBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqnoBytes, seqno)

	// Compute HMAC
	mac := s.computeHMAC(seqnoBytes, issuerID)

	// Combine seqno + HMAC
	data := append(seqnoBytes, mac...)

	// Write atomically: write to temp file, then rename
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write seqno file: %w", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath) // Clean up temp file on error
		return fmt.Errorf("failed to rename seqno file: %w", err)
	}

	return nil
}

// seqnoPath returns the file path for an issuer's sequence number
func (s *FileStorage) seqnoPath(issuerID string) string {
	// Use hex encoding to avoid filesystem issues with special characters
	safe := hex.EncodeToString([]byte(issuerID))
	return filepath.Join(s.dir, safe+".seqno")
}

// computeHMAC computes HMAC-SHA256 over seqno || issuerID
// This binds the seqno to a specific issuer, preventing cross-issuer attacks
func (s *FileStorage) computeHMAC(seqnoBytes []byte, issuerID string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(seqnoBytes)
	h.Write([]byte(issuerID))
	return h.Sum(nil)
}

// Verify that FileStorage implements the Storage interface
var _ types.Storage = (*FileStorage)(nil)
