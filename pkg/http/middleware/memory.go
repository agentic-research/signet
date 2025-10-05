package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// MemoryTokenStore implements TokenStore using in-memory storage.
// Suitable for single-instance deployments and testing.
type MemoryTokenStore struct {
	mu        sync.RWMutex
	tokens    map[string]*TokenRecord
	stopClean chan struct{}
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	store := &MemoryTokenStore{
		tokens:    make(map[string]*TokenRecord),
		stopClean: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Get retrieves a token record by ID
func (s *MemoryTokenStore) Get(ctx context.Context, tokenID string) (*TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.tokens[tokenID]
	if !exists {
		return nil, ErrTokenNotFound
	}

	return record, nil
}

// Store saves a token record and returns its ID
func (s *MemoryTokenStore) Store(ctx context.Context, record *TokenRecord) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate token ID from full JTI (use full hash to prevent collisions - Finding #26 fix)
	if len(record.Token.JTI) == 0 {
		return "", fmt.Errorf("token missing jti")
	}

	tokenID := hex.EncodeToString(record.Token.JTI)
	s.tokens[tokenID] = record

	return tokenID, nil
}

// Delete removes a token record
func (s *MemoryTokenStore) Delete(ctx context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, tokenID)
	return nil
}

// Cleanup removes expired tokens
func (s *MemoryTokenStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, record := range s.tokens {
		// Remove tokens expired for more than 5 minutes
		expiryTime := time.Unix(record.Token.ExpiresAt, 0)
		if now.Sub(expiryTime) > 5*time.Minute {
			delete(s.tokens, id)
		}
	}

	return nil
}

// Close stops the cleanup goroutine
func (s *MemoryTokenStore) Close() {
	close(s.stopClean)
}

// cleanupLoop periodically removes expired tokens
func (s *MemoryTokenStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = s.Cleanup(context.Background())
		case <-s.stopClean:
			return
		}
	}
}

// MemoryNonceStore implements NonceStore using in-memory storage.
// Suitable for single-instance deployments and testing.
type MemoryNonceStore struct {
	mu        sync.RWMutex
	nonces    map[string]time.Time // nonce_key -> expiry
	stopClean chan struct{}
}

// NewMemoryNonceStore creates a new in-memory nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	store := &MemoryNonceStore{
		nonces:    make(map[string]time.Time),
		stopClean: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// CheckAndStore atomically checks and stores a nonce
func (s *MemoryNonceStore) CheckAndStore(ctx context.Context, nonceKey string, expiry int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if nonce already exists
	if _, exists := s.nonces[nonceKey]; exists {
		return ErrReplayDetected
	}

	// Store nonce with expiry
	s.nonces[nonceKey] = time.Unix(expiry, 0)
	return nil
}

// Cleanup removes expired nonces
func (s *MemoryNonceStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, expiry := range s.nonces {
		// Remove nonces past their expiry
		if now.After(expiry) {
			delete(s.nonces, key)
		}
	}

	return nil
}

// Close stops the cleanup goroutine
func (s *MemoryNonceStore) Close() {
	close(s.stopClean)
}

// cleanupLoop periodically removes expired nonces
func (s *MemoryNonceStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = s.Cleanup(context.Background())
		case <-s.stopClean:
			return
		}
	}
}

// MultiKeyProvider implements KeyProvider with support for multiple issuers
type MultiKeyProvider struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewMultiKeyProvider creates a key provider supporting multiple issuers
func NewMultiKeyProvider() *MultiKeyProvider {
	return &MultiKeyProvider{
		keys: make(map[string]ed25519.PublicKey),
	}
}

// AddKey registers a master public key for an issuer
func (p *MultiKeyProvider) AddKey(issuerID string, key ed25519.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[issuerID] = key
}

// GetMasterKey retrieves the master public key for an issuer
func (p *MultiKeyProvider) GetMasterKey(ctx context.Context, issuerID string) (ed25519.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, exists := p.keys[issuerID]
	if !exists {
		return nil, fmt.Errorf("%w: issuer %s", ErrKeyNotFound, issuerID)
	}

	return key, nil
}

// RefreshKeys is a no-op for the in-memory provider
func (p *MultiKeyProvider) RefreshKeys(ctx context.Context) error {
	return nil
}
