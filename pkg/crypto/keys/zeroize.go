package keys

import (
	"crypto"
	"crypto/ed25519"
	"runtime"

	"github.com/jamestexas/signet/pkg/crypto/algorithm"
)

// ZeroizePrivateKey securely zeros an Ed25519 private key from memory.
// It uses runtime.KeepAlive to prevent the compiler from optimizing out
// the zeroization operation.
//
// Usage:
//
//	privateKey := ed25519.PrivateKey{...}
//	defer ZeroizePrivateKey(privateKey)
func ZeroizePrivateKey(key ed25519.PrivateKey) {
	if key == nil {
		return
	}
	// Zero each byte of the key
	for i := range key {
		key[i] = 0
	}
	// Prevent compiler optimization from removing the zeroization
	runtime.KeepAlive(key)
}

// ZeroizeBytes securely zeros a byte slice from memory.
// It uses runtime.KeepAlive to prevent the compiler from optimizing out
// the zeroization operation.
//
// Usage:
//
//	secret := []byte{...}
//	defer ZeroizeBytes(secret)
func ZeroizeBytes(b []byte) {
	if b == nil {
		return
	}
	// Zero each byte
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler optimization from removing the zeroization
	runtime.KeepAlive(b)
}

// SecurePrivateKey wraps a private key with automatic cleanup.
// Supports Ed25519 and any algorithm registered in the algorithm registry.
// The key is automatically zeroed when the wrapper is destroyed.
type SecurePrivateKey struct {
	rawKey    crypto.PrivateKey
	key       ed25519.PrivateKey // kept for backward compat with Key() method
	destroyed bool
}

// NewSecurePrivateKey creates a new SecurePrivateKey wrapper for an Ed25519 key.
// The key will be automatically zeroed when Destroy() is called.
func NewSecurePrivateKey(key ed25519.PrivateKey) *SecurePrivateKey {
	return &SecurePrivateKey{
		rawKey:    key,
		key:       key,
		destroyed: false,
	}
}

// NewSecurePrivateKeyGeneric creates a new SecurePrivateKey wrapper for any key type.
// Use this for non-Ed25519 keys (e.g., ML-DSA). The key will be zeroed via the
// algorithm registry when Destroy() is called.
func NewSecurePrivateKeyGeneric(key crypto.PrivateKey) *SecurePrivateKey {
	// If it happens to be ed25519, also populate the typed field
	edKey, ok := key.(ed25519.PrivateKey)
	if ok {
		return &SecurePrivateKey{
			rawKey:    key,
			key:       edKey,
			destroyed: false,
		}
	}
	return &SecurePrivateKey{
		rawKey:    key,
		destroyed: false,
	}
}

// Key returns the wrapped Ed25519 private key if it hasn't been destroyed.
// Returns nil if the key has been destroyed, if the receiver is nil,
// or if the underlying key is not Ed25519.
func (s *SecurePrivateKey) Key() ed25519.PrivateKey {
	if s == nil || s.destroyed {
		return nil
	}
	return s.key
}

// RawKey returns the wrapped private key regardless of algorithm type.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) RawKey() crypto.PrivateKey {
	if s == nil || s.destroyed {
		return nil
	}
	return s.rawKey
}

// Public returns the public key associated with this private key.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) Public() ed25519.PublicKey {
	if s == nil || s.destroyed {
		return nil
	}
	// Backward compat: return typed Ed25519 public key
	if s.key != nil {
		return s.key.Public().(ed25519.PublicKey)
	}
	return nil
}

// PublicKey returns the public key for any algorithm type.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) PublicKey() crypto.PublicKey {
	if s == nil || s.destroyed {
		return nil
	}
	if signer, ok := s.rawKey.(crypto.Signer); ok {
		return signer.Public()
	}
	return nil
}

// Sign signs the given message with the private key.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) Sign(message []byte) []byte {
	if s == nil || s.destroyed {
		return nil
	}
	if s.key != nil {
		return ed25519.Sign(s.key, message)
	}
	return nil
}

// Destroy securely zeros the private key from memory.
// After calling Destroy, the key cannot be used.
// This is idempotent - calling multiple times is safe.
// Safe to call on nil receiver.
//
// IMPORTANT: Ed25519 keys are fully zeroized. ML-DSA-44 keys have limited zeroization
// due to cloudflare/circl API limitations - the serialized representation is zeroed,
// but internal struct fields may persist. For production use of ML-DSA master keys,
// implement key rotation policies and coordinate with security team.
func (s *SecurePrivateKey) Destroy() {
	if s != nil && !s.destroyed {
		if s.key != nil {
			ZeroizePrivateKey(s.key)
		} else if s.rawKey != nil {
			algorithm.ZeroizePrivateKey(s.rawKey)
		}
		s.destroyed = true
	}
}

// GenerateSecureKeyPair generates a new Ed25519 key pair with automatic cleanup.
// The returned SecurePrivateKey will automatically zero the private key when destroyed.
//
// Usage:
//
//	pub, secPriv, err := GenerateSecureKeyPair()
//	if err != nil {
//	    return err
//	}
//	defer secPriv.Destroy()
func GenerateSecureKeyPair() (ed25519.PublicKey, *SecurePrivateKey, error) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pub, NewSecurePrivateKey(priv), nil
}

// GenerateSecureKeyPairForAlgorithm generates a key pair for the specified algorithm.
// The returned SecurePrivateKey will automatically zero the private key when destroyed.
func GenerateSecureKeyPairForAlgorithm(alg algorithm.Algorithm) (crypto.PublicKey, *SecurePrivateKey, error) {
	ops, err := algorithm.Get(alg)
	if err != nil {
		return nil, nil, err
	}
	pub, signer, err := ops.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	// crypto.Signer embeds crypto.PrivateKey in most implementations
	return pub, NewSecurePrivateKeyGeneric(signer.(crypto.PrivateKey)), nil
}
