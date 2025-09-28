package main

import (
	"os"
	"path/filepath"
)

// Config holds the configuration for signet-commit
type Config struct {
	// KeyPath is the path to the master key file
	KeyPath string

	// IssuerDID is the DID of the signer
	IssuerDID string

	// CertificateValidity is the duration for ephemeral certificates
	CertificateValidityMinutes int
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	// Implementation will follow
	// Default key path: ~/.signet/master.key
	// Default DID: derived from master key
	// Default validity: 5 minutes
	return nil
}

// LoadConfig loads configuration from environment and files
func LoadConfig() (*Config, error) {
	// Implementation will follow
	// Check environment variables
	// Check config file (~/.signet/config)
	// Fall back to defaults
	return nil, nil
}

// GetDefaultKeyPath returns the default path for the master key
func GetDefaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".signet", "master.key")
}

// GetDefaultConfigPath returns the default path for the config file
func GetDefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".signet", "config")
}

// EnsureSignetDirectory creates the ~/.signet directory if it doesn't exist
func EnsureSignetDirectory() error {
	// Implementation will follow
	return nil
}
