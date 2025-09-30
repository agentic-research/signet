// Package main implements the Signet Authority service
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the Signet Authority configuration
type Config struct {
	// OIDC configuration
	OIDCProviderURL  string `json:"oidc_provider_url"`
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"oidc_client_secret"`
	RedirectURL      string `json:"redirect_url"` // e.g., "http://localhost:8080/callback"

	// Authority configuration
	AuthorityMasterKey string `json:"authority_master_key_path"`

	// Server configuration
	ListenAddr string `json:"listen_addr"`

	// Certificate configuration
	CertificateValidity int `json:"certificate_validity_hours"` // Default: 8 hours

	// Session configuration
	SessionSecret string `json:"session_secret"` // For secure cookies
}

// LoadConfig loads configuration from a given path
func LoadConfig(path string) (*Config, error) {
	// Open the configuration file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Decode the JSON configuration
	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	// Validate required fields
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set defaults
	if config.CertificateValidity == 0 {
		config.CertificateValidity = 8 // Default to 8 hours
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":8080" // Default to port 8080
	}

	return &config, nil
}

// validate checks that all required configuration fields are present
func (c *Config) validate() error {
	if c.OIDCProviderURL == "" {
		return fmt.Errorf("oidc_provider_url is required")
	}

	if c.OIDCClientID == "" {
		return fmt.Errorf("oidc_client_id is required")
	}

	if c.OIDCClientSecret == "" {
		return fmt.Errorf("oidc_client_secret is required")
	}

	if c.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}

	if c.AuthorityMasterKey == "" {
		return fmt.Errorf("authority_master_key_path is required")
	}

	if c.SessionSecret == "" {
		return fmt.Errorf("session_secret is required")
	}

	return nil
}
