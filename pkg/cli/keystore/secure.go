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
	defer keys.ZeroizePrivateKey(priv)

	// Store the seed (32 bytes) as hex in keyring
	seed := priv.Seed()
	defer keys.ZeroizeBytes(seed)

	seedHex := hex.EncodeToString(seed)
	seedHexBytes := []byte(seedHex)
	defer keys.ZeroizeBytes(seedHexBytes)

	// Store in OS keyring
	if err := keyring.Set(ServiceName, MasterKeyItem, seedHex); err != nil {
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

	// Convert string to byte slice for proper zeroization
	seedHexBytes := []byte(seedHex)
	defer keys.ZeroizeBytes(seedHexBytes)

	// Decode hex to seed
	seed, err := hex.DecodeString(string(seedHexBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key from keyring: %w", err)
	}

	// Ensure seed is zeroed on all exit paths
	defer keys.ZeroizeBytes(seed)

	// Validate seed size
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: got %d, expected %d", len(seed), ed25519.SeedSize)
	}

	// Reconstruct private key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)

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

	// Convert string to byte slice for proper zeroization
	seedHexBytes := []byte(seedHex)
	defer keys.ZeroizeBytes(seedHexBytes)

	// Decode hex to seed
	seed, err := hex.DecodeString(string(seedHexBytes))
	if err != nil {
		return "", fmt.Errorf("failed to decode key: %w", err)
	}

	// Ensure seed is zeroed on all exit paths
	defer keys.ZeroizeBytes(seed)

	if len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid seed size")
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
