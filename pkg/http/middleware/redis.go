//go:build redis
// +build redis

package middleware

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
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
	// Deserialize public keys using stored algorithm information for proper type reconstruction
	masterPub, err := deserializePublicKey(stored.MasterPublicKeyAlgorithm, stored.MasterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize master public key: %w", err)
	}
	ephemeralPub, err := deserializePublicKey(stored.EphemeralPublicKeyAlgorithm, stored.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize ephemeral public key: %w", err)
	}

	record := &TokenRecord{
		Token:              stored.Token,
		MasterPublicKey:    masterPub,
		EphemeralPublicKey: ephemeralPub,
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

	// Marshal public keys to bytes for storage, capturing algorithm for deserialization
	masterKeyBytes, masterAlg, err := marshalPublicKeyWithAlgorithm(record.MasterPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal master public key: %w", err)
	}
	ephemeralKeyBytes, ephemeralAlg, err := marshalPublicKeyWithAlgorithm(record.EphemeralPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ephemeral public key: %w", err)
	}

	// Convert to storable format
	stored := storedTokenRecord{
		Token:                       record.Token,
		MasterPublicKeyAlgorithm:    masterAlg,
		MasterPublicKey:             masterKeyBytes,
		EphemeralPublicKeyAlgorithm: ephemeralAlg,
		EphemeralPublicKey:          ephemeralKeyBytes,
		BindingSignature:            record.BindingSignature,
		IssuedAt:                    record.IssuedAt,
		Purpose:                     record.Purpose,
		Metadata:                    record.Metadata,
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
	Token                       *signet.Token     `json:"token"`
	MasterPublicKeyAlgorithm    string            `json:"master_public_key_algorithm"`
	MasterPublicKey             []byte            `json:"master_public_key"`
	EphemeralPublicKeyAlgorithm string            `json:"ephemeral_public_key_algorithm"`
	EphemeralPublicKey          []byte            `json:"ephemeral_public_key"`
	BindingSignature            []byte            `json:"binding_signature"`
	IssuedAt                    time.Time         `json:"issued_at"`
	Purpose                     string            `json:"purpose"`
	Metadata                    map[string]string `json:"metadata,omitempty"`
}

// generateTokenID generates a consistent token ID from a record
func generateTokenID(record *TokenRecord) string {
	return hex.EncodeToString(record.Token.EphemeralKeyID[:min(8, len(record.Token.EphemeralKeyID))])
}

// marshalPublicKeyWithAlgorithm marshals a public key to bytes and returns the algorithm name.
// This enables algorithm-aware deserialization in Redis.
func marshalPublicKeyWithAlgorithm(pub crypto.PublicKey) ([]byte, string, error) {
	// Try each algorithm to determine which one owns this key type
	for _, alg := range []string{"ed25519", "ml-dsa-44"} {
		algType := algorithm.Algorithm(alg)
		ops, err := algorithm.Get(algType)
		if err != nil {
			continue
		}
		b, err := ops.MarshalPublicKey(pub)
		if err == nil {
			return b, alg, nil
		}
	}
	return nil, "", fmt.Errorf("unsupported public key type: %T", pub)
}

// deserializePublicKey reconstructs a public key from bytes using the stored algorithm.
// This ensures ML-DSA keys are not misinterpreted as Ed25519 keys (CVE-equivalent fix).
func deserializePublicKey(algName string, keyBytes []byte) (crypto.PublicKey, error) {
	if algName == "" {
		// Backward compatibility: empty algorithm means Ed25519
		algName = "ed25519"
	}

	algType := algorithm.Algorithm(algName)
	if !algType.Valid() {
		return nil, fmt.Errorf("unsupported algorithm: %s", algName)
	}

	ops, err := algorithm.Get(algType)
	if err != nil {
		return nil, err
	}

	// ML-DSA: reconstruct *mldsa44.PublicKey from bytes
	// Ed25519: construct ed25519.PublicKey from bytes
	switch algType {
	case algorithm.Ed25519:
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 public key size: expected 32, got %d", len(keyBytes))
		}
		return ed25519.PublicKey(keyBytes), nil
	case algorithm.MLDSA44:
		pub := &mldsa44.PublicKey{}
		var buf [mldsa44.PublicKeySize]byte
		if len(keyBytes) != mldsa44.PublicKeySize {
			return nil, fmt.Errorf("invalid ML-DSA-44 public key size: expected %d, got %d", mldsa44.PublicKeySize, len(keyBytes))
		}
		copy(buf[:], keyBytes)
		pub.Unpack(&buf)
		return pub, nil
	default:
		return nil, fmt.Errorf("algorithm deserialization not implemented: %s", algName)
	}
}
