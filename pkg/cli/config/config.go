package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DefaultCertificateValidityMinutes is the default duration for ephemeral certificates
	DefaultCertificateValidityMinutes = 5
)

// Config holds the configuration for Signet CLI
type Config struct {
	// Home is the path to the .signet directory
	Home string

	// KeyPath is the path to the master key file
	KeyPath string

	// IssuerDID is the DID of the signer
	IssuerDID string

	// CertificateValidityMinutes is the duration for ephemeral certificates
	CertificateValidityMinutes int
}

// Default returns the default configuration
func Default() *Config {
	home := GetDefaultHome()
	return &Config{
		Home:                       home,
		KeyPath:                    filepath.Join(home, "master.key"),
		IssuerDID:                  "did:key:signet",
		CertificateValidityMinutes: DefaultCertificateValidityMinutes,
	}
}

// Load loads configuration from environment variables and defaults
// Priority: env vars > defaults
func Load() (*Config, error) {
	cfg := Default()

	// Override with environment variables if set
	if home := os.Getenv("SIGNET_HOME"); home != "" {
		cfg.Home = home
		cfg.KeyPath = filepath.Join(home, "master.key")
	}

	if keyPath := os.Getenv("SIGNET_KEY_PATH"); keyPath != "" {
		cfg.KeyPath = keyPath
	}

	if did := os.Getenv("SIGNET_DID"); did != "" {
		cfg.IssuerDID = did
	}

	return cfg, nil
}

// GetDefaultHome returns the default path for the .signet directory
func GetDefaultHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".signet"
	}
	return filepath.Join(home, ".signet")
}

// DefaultHome is an alias for GetDefaultHome for backward compatibility
func DefaultHome() string {
	return GetDefaultHome()
}

// New creates a new Config with the given home directory
func New(home string) *Config {
	if home == "" {
		home = DefaultHome()
	}

	return &Config{
		Home:                       home,
		KeyPath:                    filepath.Join(home, "master.key"),
		IssuerDID:                  "did:key:signet",
		CertificateValidityMinutes: DefaultCertificateValidityMinutes,
	}
}

// EnsureHome creates the .signet directory if it doesn't exist
func (c *Config) EnsureHome() error {
	if err := os.MkdirAll(c.Home, 0700); err != nil {
		return fmt.Errorf("failed to create signet directory: %w", err)
	}
	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Home == "" {
		return errors.New("home directory cannot be empty")
	}

	if c.KeyPath == "" {
		return errors.New("key path cannot be empty")
	}

	if c.CertificateValidityMinutes < 1 || c.CertificateValidityMinutes > DefaultCertificateValidityMinutes {
		return fmt.Errorf("certificate validity must be between 1 and %d minutes", DefaultCertificateValidityMinutes)
	}

	return nil
}
