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

	// Store the seed (32 bytes) as hex in keyring
	seed := priv.Seed()
	seedHex := hex.EncodeToString(seed)

	// Zero the seed after encoding
	for i := range seed {
		seed[i] = 0
	}

	// Store in OS keyring
	if err := keyring.Set(ServiceName, MasterKeyItem, seedHex); err != nil {
		// Zero the hex string before returning
		for i := range seedHex {
			seedHex = seedHex[:i] + "0" + seedHex[i+1:]
		}
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	fmt.Printf("Master key generated and stored in OS keyring\n")
	fmt.Printf("Public key: %x\n", pub)
	fmt.Printf("Service: %s\n", ServiceName)
	fmt.Printf("Item: %s\n", MasterKeyItem)

	return nil
}

// LoadMasterKeySecure loads the master key from the OS keyring
func LoadMasterKeySecure() (*keys.Ed25519Signer, error) {
	// Retrieve from OS keyring
	seedHex, err := keyring.Get(ServiceName, MasterKeyItem)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("master key not found in keyring (run 'signet init' first)")
		}
		return nil, fmt.Errorf("failed to retrieve key from keyring: %w", err)
	}

	// Decode hex to seed
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		// Zero the hex string before returning
		for i := range seedHex {
			seedHex = seedHex[:i] + "0" + seedHex[i+1:]
		}
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Zero the hex string after decoding
	for i := range seedHex {
		seedHex = seedHex[:i] + "0" + seedHex[i+1:]
	}

	// Validate seed size
	if len(seed) != ed25519.SeedSize {
		// Zero the seed before returning
		for i := range seed {
			seed[i] = 0
		}
		return nil, fmt.Errorf("invalid seed size: got %d, expected %d", len(seed), ed25519.SeedSize)
	}

	// Reconstruct private key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Zero the seed after use
	for i := range seed {
		seed[i] = 0
	}

	// Note: privateKey is NOT zeroed here because NewEd25519Signer stores a reference
	// to the same underlying array. The caller must call Destroy() on the returned
	// signer to zero the private key when done.
	return keys.NewEd25519Signer(privateKey), nil
}

// GetKeyIDSecure returns the key ID (hex-encoded public key) from the OS keyring
func GetKeyIDSecure() (string, error) {
	// Retrieve from OS keyring
	seedHex, err := keyring.Get(ServiceName, MasterKeyItem)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", errors.New("master key not found in keyring")
		}
		return "", fmt.Errorf("failed to retrieve key from keyring: %w", err)
	}

	// Decode hex to seed
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode key: %w", err)
	}

	// Zero the hex string after decoding
	for i := range seedHex {
		seedHex = seedHex[:i] + "0" + seedHex[i+1:]
	}

	if len(seed) != ed25519.SeedSize {
		// Zero the seed before returning
		for i := range seed {
			seed[i] = 0
		}
		return "", errors.New("invalid seed size")
	}

	// Generate public key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Zero the seed after use
	for i := range seed {
		seed[i] = 0
	}

	// Zero the private key after extracting public key
	for i := range privateKey {
		privateKey[i] = 0
	}

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
