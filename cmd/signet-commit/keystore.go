package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jamestexas/signet/pkg/crypto/keys"
)

// initializeSignet creates the signet directory and generates a master key
func initializeSignet(signetPath string) error {
	// Create directory with restricted permissions
	if err := os.MkdirAll(signetPath, 0700); err != nil {
		return fmt.Errorf("failed to create signet directory: %w", err)
	}

	keyPath := filepath.Join(signetPath, masterKeyFile)

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
	defer keyFile.Close()

	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	// Display public key info
	fmt.Printf("Master key generated: %x\n", pub)
	fmt.Printf("Key stored at: %s\n", keyPath)

	return nil
}

// loadMasterKey loads the master key from the signet directory
func loadMasterKey(signetPath string) (*keys.Ed25519Signer, error) {
	keyPath := filepath.Join(signetPath, masterKeyFile)

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("master key not found")
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Verify permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat key file: %w", err)
	}

	// Check that only owner can read/write
	mode := info.Mode()
	if mode.Perm() != 0600 {
		return nil, fmt.Errorf("insecure key file permissions: %v (expected 0600)", mode.Perm())
	}

	// Decode PEM
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	// Reconstruct private key from seed
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("invalid seed size")
	}

	privateKey := ed25519.NewKeyFromSeed(block.Bytes)

	// Zero the seed after use
	for i := range block.Bytes {
		block.Bytes[i] = 0
	}

	return keys.NewEd25519Signer(privateKey), nil
}

// getKeyID returns the key ID for Git configuration
func getKeyID(signetPath string) (string, error) {
	keyPath := filepath.Join(signetPath, masterKeyFile)

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errors.New("master key not found")
		}
		return "", fmt.Errorf("failed to read key file: %w", err)
	}

	// Decode PEM to get seed
	block, _ := pem.Decode(keyData)
	if block == nil {
		return "", errors.New("failed to decode PEM block")
	}

	if block.Type != "ED25519 PRIVATE KEY" {
		return "", fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return "", errors.New("invalid seed size")
	}

	// Generate public key from seed
	privateKey := ed25519.NewKeyFromSeed(block.Bytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Zero the seed after use
	for i := range block.Bytes {
		block.Bytes[i] = 0
	}

	// Return hex-encoded public key as ID
	return hex.EncodeToString(publicKey), nil
}
