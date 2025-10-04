package keys

import (
	"crypto/ed25519"
	"runtime"
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

// SecurePrivateKey wraps an Ed25519 private key with automatic cleanup.
// The key is automatically zeroed when the wrapper is destroyed.
type SecurePrivateKey struct {
	key       ed25519.PrivateKey
	destroyed bool
}

// NewSecurePrivateKey creates a new SecurePrivateKey wrapper.
// The key will be automatically zeroed when Destroy() is called.
func NewSecurePrivateKey(key ed25519.PrivateKey) *SecurePrivateKey {
	return &SecurePrivateKey{
		key:       key,
		destroyed: false,
	}
}

// Key returns the wrapped private key if it hasn't been destroyed.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) Key() ed25519.PrivateKey {
	if s == nil || s.destroyed {
		return nil
	}
	return s.key
}

// Public returns the public key associated with this private key.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) Public() ed25519.PublicKey {
	if s == nil || s.destroyed {
		return nil
	}
	return s.key.Public().(ed25519.PublicKey)
}

// Sign signs the given message with the private key.
// Returns nil if the key has been destroyed or if the receiver is nil.
func (s *SecurePrivateKey) Sign(message []byte) []byte {
	if s == nil || s.destroyed {
		return nil
	}
	return ed25519.Sign(s.key, message)
}

// Destroy securely zeros the private key from memory.
// After calling Destroy, the key cannot be used.
// This is idempotent - calling multiple times is safe.
// Safe to call on nil receiver.
func (s *SecurePrivateKey) Destroy() {
	if s != nil && !s.destroyed {
		ZeroizePrivateKey(s.key)
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
