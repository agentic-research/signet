package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type AuthorityConfig struct {
	// OIDC configuration
	OIDCProviderURL  string `json:"oidc_provider_url"`
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"oidc_client_secret"`
	RedirectURL      string `json:"redirect_url"`

	// Authority configuration
	AuthorityMasterKey string `json:"authority_master_key_path"`

	// Server configuration
	ListenAddr string `json:"listen_addr"`

	// Certificate configuration
	CertificateValidity int `json:"certificate_validity_hours"`

	// OIDC provider configuration (for CI/CD platforms)
	OIDCProvidersFile string `json:"oidc_providers_file,omitempty"`

	// Session configuration - SECURITY: No longer loaded from JSON
	// Session secrets MUST be provided via SIGNET_SESSION_SECRET environment variable
	// This field is deprecated and will be ignored if present in config
	SessionSecret string `json:"session_secret,omitempty"`

	// TrustedProxyHeader specifies which header to use for client IP extraction.
	// Set to "CF-Connecting-IP" behind Cloudflare, "X-Real-IP" behind nginx,
	// or empty to use RemoteAddr only (safest when not behind a proxy).
	// Default: "" (RemoteAddr only — does not trust any forwarded headers).
	TrustedProxyHeader string `json:"trusted_proxy_header,omitempty"`

	// MaxCertValidityHours is the hard upper bound for any certificate validity.
	// Prevents misconfiguration from issuing long-lived certs.
	// Default: 24 hours. Set to 0 to use default.
	MaxCertValidityHours int `json:"max_cert_validity_hours,omitempty"`

	// MaxRateLimiterEntries caps the per-IP rate limiter map size to prevent
	// memory exhaustion from spoofed IPs. Default: 100000.
	MaxRateLimiterEntries int `json:"max_rate_limiter_entries,omitempty"`
}

func loadAuthorityConfig(path string) (*AuthorityConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var config AuthorityConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	// SECURITY: Load session secret from environment variable only
	// This prevents secrets from being stored in configuration files
	sessionSecret := os.Getenv("SIGNET_SESSION_SECRET")
	if sessionSecret == "" {
		return nil, fmt.Errorf("SIGNET_SESSION_SECRET environment variable is required")
	}
	if len(sessionSecret) < 32 {
		return nil, fmt.Errorf("SIGNET_SESSION_SECRET must be at least 32 characters for security")
	}
	config.SessionSecret = sessionSecret

	// Validate required fields
	if err := validateAuthorityConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set defaults
	if config.CertificateValidity == 0 {
		config.CertificateValidity = 8
	}
	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}
	if config.MaxCertValidityHours <= 0 {
		config.MaxCertValidityHours = 24
	}
	if config.MaxRateLimiterEntries <= 0 {
		config.MaxRateLimiterEntries = 100000
	}

	return &config, nil
}

func validateAuthorityConfig(c *AuthorityConfig) error {
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
	// Note: SessionSecret is NOT validated here. It is loaded exclusively from
	// the SIGNET_SESSION_SECRET environment variable and validated in
	// loadAuthorityConfig() to prevent secrets from appearing in config files.
	return nil
}
