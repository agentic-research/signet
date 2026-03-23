package keystore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/agentic-research/signet/pkg/lifecycle"
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

// parseKeyringValue parses the keyring storage format.
// Format: "algorithm:hex-seed" (new) or plain hex (legacy Ed25519).
// Returns (algorithm, seed, error).
func parseKeyringValue(value string) (algorithm.Algorithm, []byte, error) {
	var alg algorithm.Algorithm
	var seedHex string

	if idx := strings.Index(value, ":"); idx > 0 {
		// New format: "algorithm:hex-seed"
		alg = algorithm.Algorithm(value[:idx])
		seedHex = value[idx+1:]
	} else {
		// Legacy format: plain hex = Ed25519
		alg = algorithm.Ed25519
		seedHex = value
	}

	if !alg.Valid() {
		return "", nil, fmt.Errorf("unsupported algorithm in keyring: %s", alg)
	}

	ops, err := algorithm.Get(alg)
	if err != nil {
		return "", nil, err
	}

	expectedHexLen := ops.SeedSize() * 2
	if len(seedHex) != expectedHexLen {
		return "", nil, errors.New("invalid key data in keyring")
	}

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return "", nil, errors.New("invalid key data in keyring")
	}

	if len(seed) != ops.SeedSize() {
		keys.ZeroizeBytes(seed)
		return "", nil, errors.New("invalid key data in keyring")
	}

	return alg, seed, nil
}

// retrieveSeedFromKeyring handles the common pattern of getting and decoding seed from keyring.
// Returns (algorithm, seed, error).
func retrieveSeedFromKeyring() (algorithm.Algorithm, []byte, error) {
	seedHex, err := keyring.Get(ServiceName, MasterKeyItem)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", nil, errors.New("master key not found in keyring (run 'signet init' first)")
		}
		return "", nil, errors.New("failed to retrieve key from keyring")
	}

	return parseKeyringValue(seedHex)
}

// seedToSignerAndPublicKey creates a signer and public key from a seed using the given algorithm.
func seedToSignerAndPublicKey(alg algorithm.Algorithm, seed []byte) (crypto.PublicKey, crypto.Signer, error) {
	ops, err := algorithm.Get(alg)
	if err != nil {
		return nil, nil, err
	}
	pub, signer, err := ops.GenerateKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	return pub, signer, nil
}

// seedToPublicKeyHex converts a seed to hex-encoded public key (Ed25519 only, for backward compat)
func seedToPublicKeyHex(seed []byte) string {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keys.ZeroizePrivateKey(privateKey)
	return hex.EncodeToString(publicKey)
}

// publicKeyHex returns a hex-encoded representation of any public key.
func publicKeyHex(alg algorithm.Algorithm, pub crypto.PublicKey) (string, error) {
	ops, err := algorithm.Get(alg)
	if err != nil {
		return "", err
	}
	b, err := ops.MarshalPublicKey(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
		if mode.Perm()&0o077 != 0 { // Check group/other bits are zero
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

// InitializeSecure generates a master key and stores it in the OS keyring.
// The alg parameter specifies which algorithm to use (empty string defaults to Ed25519).
func InitializeSecure(force bool, alg ...algorithm.Algorithm) error {
	// Determine algorithm
	selectedAlg := algorithm.DefaultAlgorithm
	if len(alg) > 0 && alg[0] != "" {
		selectedAlg = alg[0]
	}

	ops, err := algorithm.Get(selectedAlg)
	if err != nil {
		return fmt.Errorf("unsupported algorithm: %w", err)
	}

	// Check if key already exists
	_, err = keyring.Get(ServiceName, MasterKeyItem)
	if err == nil {
		if !force {
			return errors.New("master key already exists in keyring (use --force to overwrite)")
		}
		// Delete existing key when forcing
		if err := keyring.Delete(ServiceName, MasterKeyItem); err != nil {
			return fmt.Errorf("failed to delete existing key from keyring: %w", err)
		}
	}

	// Generate seed
	seed := make([]byte, ops.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to generate random seed: %w", err)
	}

	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	return lifecycle.WithSecureValue(seed, seedZeroizer, func(secureSeed *[]byte) error {
		// Derive public key for display
		pub, _, err := ops.GenerateKeyFromSeed(*secureSeed)
		if err != nil {
			return fmt.Errorf("failed to derive key from seed: %w", err)
		}

		// Encode to hex with nested loan pattern
		seedHexBytes := make([]byte, hex.EncodedLen(len(*secureSeed)))
		hex.Encode(seedHexBytes, *secureSeed)
		hexZeroizer := func(h *[]byte) {
			keys.ZeroizeBytes(*h)
		}

		return lifecycle.WithSecureValue(seedHexBytes, hexZeroizer, func(secureHex *[]byte) error {
			// Build storage value: "algorithm:hex-seed"
			var storeValue string
			if selectedAlg == algorithm.Ed25519 {
				// Legacy format for Ed25519 backward compat
				storeValue = string(*secureHex)
			} else {
				storeValue = string(selectedAlg) + ":" + string(*secureHex)
			}

			// Store in OS keyring
			if err := keyring.Set(ServiceName, MasterKeyItem, storeValue); err != nil {
				return fmt.Errorf("failed to store key in keyring: %w", err)
			}

			pubHex, err := publicKeyHex(selectedAlg, pub)
			if err != nil {
				pubHex = "[error encoding public key]"
			}

			fmt.Printf("Master key generated and stored in OS keyring\n")
			fmt.Printf("Algorithm: %s\n", selectedAlg)
			if len(pubHex) > 32 {
				fmt.Printf("Public key: %s...%s\n", pubHex[:16], pubHex[len(pubHex)-16:])
			} else {
				fmt.Printf("Public key: %s\n", pubHex)
			}
			fmt.Printf("Service: %s\n", ServiceName)
			fmt.Printf("Item: %s\n", MasterKeyItem)

			return nil
		})
	})
}

// LoadMasterKeySecure loads the master key from the OS keyring.
// Returns a crypto.Signer that the caller must Destroy() when done
// (if the signer implements a Destroy() method).
//
// SECURITY: This function returns a key derived from a secret that is loaded
// into memory as a string. Due to Go's string immutability, the secret may
// persist in memory until garbage collected. See package-level documentation
// for more details.
func LoadMasterKeySecure() (*keys.Ed25519Signer, error) {
	alg, seed, err := retrieveSeedFromKeyring()
	if err != nil {
		return nil, err
	}

	// For backward compat, the original function returns *keys.Ed25519Signer.
	// Non-Ed25519 keys should use LoadMasterKeySecureGeneric().
	if alg != algorithm.Ed25519 {
		keys.ZeroizeBytes(seed)
		return nil, fmt.Errorf("keyring contains %s key; use LoadMasterKeySecureGeneric() for non-Ed25519 keys", alg)
	}

	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	return lifecycle.WithSecureValueResult(seed, seedZeroizer, func(secureSeed *[]byte) (*keys.Ed25519Signer, error) {
		privateKey := ed25519.NewKeyFromSeed(*secureSeed)
		return keys.NewEd25519Signer(privateKey), nil
	})
}

// LoadMasterKeySecureGeneric loads any algorithm's master key from the OS keyring.
// Returns the algorithm used and a crypto.Signer.
func LoadMasterKeySecureGeneric() (algorithm.Algorithm, crypto.Signer, error) {
	alg, seed, err := retrieveSeedFromKeyring()
	if err != nil {
		return "", nil, err
	}

	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	type result struct {
		alg    algorithm.Algorithm
		signer crypto.Signer
	}

	r, err := lifecycle.WithSecureValueResult(seed, seedZeroizer, func(secureSeed *[]byte) (result, error) {
		_, signer, err := seedToSignerAndPublicKey(alg, *secureSeed)
		if err != nil {
			return result{}, err
		}
		return result{alg: alg, signer: signer}, nil
	})
	if err != nil {
		return "", nil, err
	}
	return r.alg, r.signer, nil
}

// GetKeyIDSecure returns the key ID (hex-encoded public key) from the OS keyring
//
// SECURITY: This function accesses a secret that is loaded into memory as a
// string. Due to Go's string immutability, the secret may persist in memory
// until garbage collected. See package-level documentation for more details.
func GetKeyIDSecure() (string, error) {
	alg, seed, err := retrieveSeedFromKeyring()
	if err != nil {
		return "", err
	}

	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	return lifecycle.WithSecureValueResult(seed, seedZeroizer, func(secureSeed *[]byte) (string, error) {
		pub, _, err := seedToSignerAndPublicKey(alg, *secureSeed)
		if err != nil {
			return "", err
		}
		return publicKeyHex(alg, pub)
	})
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

// InitializeInsecure generates a master key and stores it in a file (for testing).
// Only supports Ed25519 (file-based storage is for testing/fallback).
func InitializeInsecure(signetPath string, force bool) error {
	// Create directory with restricted permissions
	if err := os.MkdirAll(signetPath, 0o700); err != nil {
		return fmt.Errorf("failed to create signet directory: %w", err)
	}

	keyPath := filepath.Join(signetPath, "master.key")

	// Check if key already exists
	if _, err := os.Stat(keyPath); err == nil {
		if !force {
			return errors.New("master key already exists (use --force to overwrite)")
		}
		// Remove existing key when forcing
		if err := os.Remove(keyPath); err != nil {
			return fmt.Errorf("failed to remove existing key: %w", err)
		}
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
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
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

	// Use loan pattern to ensure seed is zeroized
	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	return lifecycle.WithSecureValueResult(seed, seedZeroizer, func(secureSeed *[]byte) (*keys.Ed25519Signer, error) {
		privateKey := ed25519.NewKeyFromSeed(*secureSeed)
		return keys.NewEd25519Signer(privateKey), nil
	})
}

// GetKeyIDInsecure returns the key ID from a file (for testing)
func GetKeyIDInsecure(signetPath string) (string, error) {
	keyPath := filepath.Join(signetPath, "master.key")

	// Read seed without permission checking (for backward compatibility)
	seed, err := readSeedFromPEM(keyPath, false)
	if err != nil {
		return "", err
	}

	// Use loan pattern to ensure seed is zeroized
	seedZeroizer := func(s *[]byte) {
		keys.ZeroizeBytes(*s)
	}

	return lifecycle.WithSecureValueResult(seed, seedZeroizer, func(secureSeed *[]byte) (string, error) {
		return seedToPublicKeyHex(*secureSeed), nil
	})
}
