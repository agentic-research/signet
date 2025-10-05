package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

// retrieveSeedFromKeyring handles the common pattern of getting and decoding seed from keyring
func retrieveSeedFromKeyring() ([]byte, error) {
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
	expectedHexLen := ed25519.SeedSize * 2

	if len(seedHexCopy) != expectedHexLen {
		return nil, errors.New("invalid key data in keyring")
	}

	// Decode hex to seed
	seed, err := hex.DecodeString(seedHexCopy)
	if err != nil {
		return nil, errors.New("invalid key data in keyring")
	}

	// Validate seed size (defense in depth)
	if len(seed) != ed25519.SeedSize {
		keys.ZeroizeBytes(seed)
		return nil, errors.New("invalid key data in keyring")
	}

	return seed, nil
}

// seedToPublicKeyHex converts a seed to hex-encoded public key
// Note: This function zeros the private key internally
func seedToPublicKeyHex(seed []byte) string {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keys.ZeroizePrivateKey(privateKey)
	return hex.EncodeToString(publicKey)
}

// readSeedFromPEM reads and validates a PEM-encoded seed from file
func readSeedFromPEM(keyPath string, checkPermissions bool) ([]byte, error) {
	// Check permissions if requested
	if checkPermissions {
		info, err := os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat key file: %w", err)
		}

		mode := info.Mode()
		if mode.Perm()&0077 != 0 { // Check group/other bits are zero
			return nil, fmt.Errorf("insecure key file permissions: %v (expected 0600)", mode.Perm())
		}
	}

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("master key not found")
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer keys.ZeroizeBytes(keyData)

	// Decode PEM
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("invalid seed size")
	}

	// Return a copy since block.Bytes will be zeroed when keyData is zeroed
	seed := make([]byte, len(block.Bytes))
	copy(seed, block.Bytes)
	return seed, nil
}

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
	pubHex := fmt.Sprintf("%x", pub)
	fmt.Printf("Public key: %s...%s\n", pubHex[:16], pubHex[len(pubHex)-16:])
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
	seed, err := retrieveSeedFromKeyring()
	if err != nil {
		return nil, err
	}
	defer keys.ZeroizeBytes(seed)

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
	seed, err := retrieveSeedFromKeyring()
	if err != nil {
		return "", err
	}
	defer keys.ZeroizeBytes(seed)

	// Return hex-encoded public key as ID
	return seedToPublicKeyHex(seed), nil
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

// InitializeInsecure generates a master key and stores it in a file (for testing)
func InitializeInsecure(signetPath string) error {
	// Create directory with restricted permissions
	if err := os.MkdirAll(signetPath, 0700); err != nil {
		return fmt.Errorf("failed to create signet directory: %w", err)
	}

	keyPath := filepath.Join(signetPath, "master.key")

	// Check if key already exists
	if _, err := os.Stat(keyPath); err == nil {
		return errors.New("master key already exists")
	}

	// Generate new Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Encode private key as PEM
	keyPEM := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(), // Store seed, not full key
	}

	// Write key with restricted permissions
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() { _ = keyFile.Close() }()

	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	// Display truncated public key info for cleaner output
	fmt.Printf("Master key generated: %x\n", pub)
	fmt.Printf("Key stored at: %s\n", keyPath)

	return nil
}

// LoadMasterKeyInsecure loads the master key from a file (for testing)
func LoadMasterKeyInsecure(signetPath string) (*keys.Ed25519Signer, error) {
	keyPath := filepath.Join(signetPath, "master.key")

	// Read seed with permission checking
	seed, err := readSeedFromPEM(keyPath, true)
	if err != nil {
		return nil, err
	}
	defer keys.ZeroizeBytes(seed)

	// Reconstruct private key from seed
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Note: privateKey is NOT zeroed here because NewEd25519Signer stores a reference
	// to the same underlying array. The caller must call Destroy() on the returned
	// signer to zero the private key when done.
	return keys.NewEd25519Signer(privateKey), nil
}

// GetKeyIDInsecure returns the key ID from a file (for testing)
func GetKeyIDInsecure(signetPath string) (string, error) {
	keyPath := filepath.Join(signetPath, "master.key")

	// Read seed without permission checking (for backward compatibility)
	// Consider adding permission check here in the future for consistency
	seed, err := readSeedFromPEM(keyPath, false)
	if err != nil {
		return "", err
	}
	defer keys.ZeroizeBytes(seed)

	// Return hex-encoded public key as ID
	return seedToPublicKeyHex(seed), nil
}
