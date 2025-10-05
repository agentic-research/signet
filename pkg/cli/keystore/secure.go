package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jamestexas/signet/pkg/crypto/keys"
	"github.com/zalando/go-keyring"
)

const (
	// ServiceName is the identifier used in the OS keyring
	ServiceName = "signet"
	// MasterKeyItem is the key identifier for the master key
	MasterKeyItem = "master-key"
)

// SECURITY: This package uses github.com/zalando/go-keyring, which stores
// secrets as strings. Go's string immutability means that even after zeroing
// the byte slice copy of a secret, the original string may remain in memory
// until the next garbage collection. This is a known limitation. An upstream
// pull request to address this is pending: https://github.com/zalando/go-keyring/pull/127

// InitializeSecure generates a master key and stores it in the OS keyring
func InitializeSecure() error {
	// Check if key already exists
	_, err := keyring.Get(ServiceName, MasterKeyItem)
	if err == nil {
		return errors.New("master key already exists in keyring")
	}

	// Generate new Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}
	defer keys.ZeroizePrivateKey(priv)

	// Store the seed (32 bytes) as hex in keyring
	seed := priv.Seed()
	defer keys.ZeroizeBytes(seed)

	// Encode directly to bytes to avoid creating immutable string
	seedHexBytes := make([]byte, hex.EncodedLen(len(seed)))
	hex.Encode(seedHexBytes, seed)
	defer keys.ZeroizeBytes(seedHexBytes)

	// Store in OS keyring
	if err := keyring.Set(ServiceName, MasterKeyItem, string(seedHexBytes)); err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	fmt.Printf("Master key generated and stored in OS keyring\n")
	fmt.Printf("Public key: %x\n", pub)
	fmt.Printf("Service: %s\n", ServiceName)
	fmt.Printf("Item: %s\n", MasterKeyItem)

	return nil
}

// LoadMasterKeySecure loads the master key from the OS keyring.
//
// SECURITY: This function returns a key derived from a secret that is loaded
// into memory as a string. Due to Go's string immutability, the secret may
// persist in memory until garbage collected. See package-level documentation
// for more details.
func LoadMasterKeySecure() (*keys.Ed25519Signer, error) {
	// Retrieve from OS keyring
	seedHex, err := keyring.Get(ServiceName, MasterKeyItem)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("master key not found in keyring (run 'signet init' first)")
		}
		return nil, errors.New("failed to retrieve key from keyring")
	}

	// Copy the retrieved string to avoid modifying the mock keyring's internal
	// state during tests, then immediately zero the original reference to shorten
	// the secret's lifetime in memory.
	seedHexCopy := seedHex
	seedHex = "" //nolint:ineffassign

	// Validate hex string length before decoding to prevent allocation attacks
	expectedHexLen := ed25519.SeedSize * 2
	if len(seedHexCopy) != expectedHexLen {
		return nil, errors.New("invalid key data in keyring")
	}

	// Decode hex to seed
	seed, err := hex.DecodeString(seedHexCopy)
	// Drop reference to the immutable string ASAP to shorten its lifetime.
	seedHexCopy = "" //nolint:ineffassign
	if err != nil {
		return nil, errors.New("invalid key data in keyring")
	}

	// Ensure seed is zeroed on all exit paths
	defer keys.ZeroizeBytes(seed)

	// Validate seed size (defense in depth)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid key data in keyring")
	}

	// Reconstruct private key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Note: privateKey is NOT zeroed here because NewEd25519Signer stores a reference
	// to the same underlying array. The caller must call Destroy() on the returned
	// signer to zero the private key when done.
	return keys.NewEd25519Signer(privateKey), nil
}

// GetKeyIDSecure returns the key ID (hex-encoded public key) from the OS keyring
//
// SECURITY: This function accesses a secret that is loaded into memory as a
// string. Due to Go's string immutability, the secret may persist in memory
// until garbage collected. See package-level documentation for more details.
func GetKeyIDSecure() (string, error) {
	// Retrieve from OS keyring
	seedHex, err := keyring.Get(ServiceName, MasterKeyItem)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", errors.New("master key not found in keyring")
		}
		return "", errors.New("failed to retrieve key from keyring")
	}

	// Copy the retrieved string to avoid modifying the mock keyring's internal
	// state during tests, then immediately zero the original reference to shorten
	// the secret's lifetime in memory.
	seedHexCopy := seedHex
	seedHex = "" //nolint:ineffassign

	// Validate hex string length before decoding
	expectedHexLen := ed25519.SeedSize * 2
	if len(seedHexCopy) != expectedHexLen {
		return "", errors.New("invalid key data in keyring")
	}

	// Decode hex to seed
	seed, err := hex.DecodeString(seedHexCopy)
	// Drop reference to the immutable string ASAP to shorten its lifetime.
	seedHexCopy = "" //nolint:ineffassign
	if err != nil {
		return "", errors.New("invalid key data in keyring")
	}

	// Ensure seed is zeroed on all exit paths
	defer keys.ZeroizeBytes(seed)

	// Validate seed size (defense in depth)
	if len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid key data in keyring")
	}

	// Generate public key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Zero the private key after extracting public key
	defer keys.ZeroizePrivateKey(privateKey)

	// Return hex-encoded public key as ID
	return hex.EncodeToString(publicKey), nil
}

// DeleteMasterKeySecure removes the master key from the OS keyring
func DeleteMasterKeySecure() error {
	if err := keyring.Delete(ServiceName, MasterKeyItem); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return errors.New("master key not found in keyring")
		}
		return fmt.Errorf("failed to delete key from keyring: %w", err)
	}

	fmt.Println("Master key deleted from OS keyring")
	return nil
}
