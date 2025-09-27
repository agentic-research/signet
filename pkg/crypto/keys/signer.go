package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Signer provides a simple interface for signing operations that aligns
// with Go's standard crypto.Signer for the MVP
type Signer interface {
	crypto.Signer
}

// Ed25519Signer implements Signer for Ed25519 keys
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	destroyed  bool
}

// NewEd25519Signer creates a new Ed25519 signer with the given private key
func NewEd25519Signer(privateKey ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{
		privateKey: privateKey,
	}
}

// Public returns the public key associated with this signer
func (s *Ed25519Signer) Public() crypto.PublicKey {
	return s.privateKey.Public()
}

// Sign creates a signature for the given message
func (s *Ed25519Signer) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.destroyed {
		return nil, errors.New("signer has been destroyed")
	}
	return s.privateKey.Sign(rand, message, opts)
}

// Destroy securely zeros the private key material
func (s *Ed25519Signer) Destroy() {
	if !s.destroyed {
		for i := range s.privateKey {
			s.privateKey[i] = 0
		}
		s.destroyed = true
	}
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenerateEd25519KeyPairFromSeed generates a deterministic Ed25519 key pair from a seed
// The seed should be 32 bytes. If using user input, stretch it with DeriveKeyFromPassword first.
func GenerateEd25519KeyPairFromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(seed) != 32 {
		// Hash the seed to get exactly 32 bytes
		hash := sha256.Sum256(seed)
		seed = hash[:]
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey, privateKey
}

// DeriveKeyFromPassword derives a 32-byte key from a password using Argon2id
func DeriveKeyFromPassword(password []byte, salt []byte) []byte {
	// Using conservative Argon2id parameters for offline use
	// Time=3, Memory=64MB, Threads=4, KeyLen=32
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	return key
}

// HashPublicKey creates a hash of a public key for use as ConfirmationID
func HashPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	pub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unsupported public key type")
	}
	hash := sha256.Sum256(pub)
	return hash[:], nil
}