//go:build redis
// +build redis

package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jamestexas/signet/pkg/signet"
)

// RedisClient defines the minimal Redis interface needed by the middleware.
// This allows using different Redis client libraries.
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) error
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)
}

// RedisTokenStore implements TokenStore using Redis.
// Suitable for distributed deployments requiring shared state.
type RedisTokenStore struct {
	client RedisClient
	prefix string
	ttl    time.Duration
}

// NewRedisTokenStore creates a Redis-backed token store.
func NewRedisTokenStore(client RedisClient, prefix string) *RedisTokenStore {
	if prefix == "" {
		prefix = "signet:tokens:"
	}
	return &RedisTokenStore{
		client: client,
		prefix: prefix,
		ttl:    10 * time.Minute, // Keep tokens for 10 minutes after expiry
	}
}

// Get retrieves a token record from Redis
func (s *RedisTokenStore) Get(ctx context.Context, tokenID string) (*TokenRecord, error) {
	key := s.prefix + tokenID

	data, err := s.client.Get(ctx, key)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	var stored storedTokenRecord
	if err := json.Unmarshal([]byte(data), &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Convert back to TokenRecord
	record := &TokenRecord{
		Token:              stored.Token,
		MasterPublicKey:    ed25519.PublicKey(stored.MasterPublicKey),
		EphemeralPublicKey: ed25519.PublicKey(stored.EphemeralPublicKey),
		BindingSignature:   stored.BindingSignature,
		IssuedAt:           stored.IssuedAt,
		Purpose:            stored.Purpose,
		Metadata:           stored.Metadata,
	}

	return record, nil
}

// Store saves a token record to Redis
func (s *RedisTokenStore) Store(ctx context.Context, record *TokenRecord) (string, error) {
	// Generate token ID
	tokenID := generateTokenID(record)
	key := s.prefix + tokenID

	// Convert to storable format
	stored := storedTokenRecord{
		Token:              record.Token,
		MasterPublicKey:    []byte(record.MasterPublicKey),
		EphemeralPublicKey: []byte(record.EphemeralPublicKey),
		BindingSignature:   record.BindingSignature,
		IssuedAt:           record.IssuedAt,
		Purpose:            record.Purpose,
		Metadata:           record.Metadata,
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Calculate TTL based on token expiry
	ttl := time.Until(time.Unix(record.Token.ExpiresAt, 0)) + s.ttl
	if ttl < 0 {
		ttl = s.ttl
	}

	if err := s.client.Set(ctx, key, data, ttl); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return tokenID, nil
}

// Delete removes a token from Redis
func (s *RedisTokenStore) Delete(ctx context.Context, tokenID string) error {
	key := s.prefix + tokenID
	return s.client.Del(ctx, key)
}

// Cleanup is not needed for Redis (TTL handles expiry)
func (s *RedisTokenStore) Cleanup(ctx context.Context) error {
	return nil
}

// RedisNonceStore implements NonceStore using Redis.
// Provides distributed replay prevention.
type RedisNonceStore struct {
	client RedisClient
	prefix string
}

// NewRedisNonceStore creates a Redis-backed nonce store.
func NewRedisNonceStore(client RedisClient, prefix string) *RedisNonceStore {
	if prefix == "" {
		prefix = "signet:nonces:"
	}
	return &RedisNonceStore{
		client: client,
		prefix: prefix,
	}
}

// CheckAndStore atomically checks and stores a nonce in Redis
func (s *RedisNonceStore) CheckAndStore(ctx context.Context, nonceKey string, expiry int64) error {
	key := s.prefix + nonceKey

	// Calculate TTL
	ttl := time.Until(time.Unix(expiry, 0)) + 5*time.Minute
	if ttl < time.Minute {
		ttl = time.Minute
	}

	// SetNX returns true if the key was set (didn't exist)
	ok, err := s.client.SetNX(ctx, key, "1", ttl)
	if err != nil {
		return fmt.Errorf("failed to check nonce: %w", err)
	}

	if !ok {
		return ErrReplayDetected
	}

	return nil
}

// Cleanup is not needed for Redis (TTL handles expiry)
func (s *RedisNonceStore) Cleanup(ctx context.Context) error {
	return nil
}

// storedTokenRecord is the JSON-serializable version of TokenRecord
type storedTokenRecord struct {
	Token              *signet.Token     `json:"token"`
	MasterPublicKey    []byte            `json:"master_public_key"`
	EphemeralPublicKey []byte            `json:"ephemeral_public_key"`
	BindingSignature   []byte            `json:"binding_signature"`
	IssuedAt           time.Time         `json:"issued_at"`
	Purpose            string            `json:"purpose"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// generateTokenID generates a consistent token ID from a record
func generateTokenID(record *TokenRecord) string {
	return hex.EncodeToString(record.Token.EphemeralKeyID[:min(8, len(record.Token.EphemeralKeyID))])
}
