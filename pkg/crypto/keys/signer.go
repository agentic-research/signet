package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Signer provides a simple interface for signing operations that aligns
// with Go's standard crypto.Signer for the MVP
type Signer interface {
	crypto.Signer
}

// Ed25519Signer implements Signer for Ed25519 keys
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
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
	return s.privateKey.Sign(rand, message, opts)
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenerateEd25519KeyPairFromSeed generates a deterministic Ed25519 key pair from a seed
func GenerateEd25519KeyPairFromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey, privateKey
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