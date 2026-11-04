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

// ErrStorageCorrupted indicates that the persistent storage HMAC verification failed
var ErrStorageCorrupted = errors.New("storage: HMAC verification failed (file may be corrupted or tampered)")

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
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
//
// The read-compare-write runs under an exclusive OS file lock on a per-issuer
// lock file, not just this instance's mutex: separate FileStorage instances
// -- in practice separate `signet verify` processes -- share only the
// directory, and without it two could both read 10 and then persist 12 and
// then 11, a regression that still carries a valid HMAC. The new value is
// written to a unique temp file, fsynced, then renamed into place, so a
// reader sees the old file or the new one, never a partial one.
func (s *FileStorage) SetLastSeenSeqnoIfGreater(ctx context.Context, issuerID string, seqno uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := s.seqnoPath(issuerID)
	unlock, err := lockPath(filePath + ".lock")
	if err != nil {
		return fmt.Errorf("lock seqno file: %w", err)
	}
	defer unlock()

	// Read current value under the lock to ensure monotonicity
	current, err := s.readSeqnoInternal(issuerID)
	if err != nil {
		return err
	}

	// Only update if new seqno is greater: the stored value is the max of
	// everything offered, never a regression.
	if seqno <= current {
		return nil // Already seen a higher or equal seqno
	}

	// Encode seqno as big-endian uint64
	seqnoBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqnoBytes, seqno)

	// Combine seqno + HMAC
	data := append(seqnoBytes, s.computeHMAC(seqnoBytes, issuerID)...)

	if err := writeFileAtomic(filePath, data); err != nil {
		return fmt.Errorf("failed to write seqno file: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to a unique temp file in path's directory,
// fsyncs it, and renames it over path.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// lockPath takes an exclusive OS-level lock on path (created if missing)
// and returns the function that releases it.
func lockPath(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 - lock file beside the storage's own seqno file
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// Path returns the file that holds issuerID's last-seen sequence number, so
// callers can tell an operator which file a rollback refusal is about.
func (s *FileStorage) Path(issuerID string) string { return s.seqnoPath(issuerID) }

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
