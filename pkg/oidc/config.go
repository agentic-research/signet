package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ProvidersConfig represents the top-level configuration for OIDC providers.
// This can be loaded from YAML or JSON files.
type ProvidersConfig struct {
	// Providers is a list of provider configurations.
	// Each provider has a "type" field that determines which implementation to use.
	Providers []ProviderConfigEntry `json:"providers" yaml:"providers"`
}

// ProviderConfigEntry represents a single provider's configuration.
// The Type field determines which provider implementation to instantiate.
type ProviderConfigEntry struct {
	// Type specifies the provider implementation (e.g., "github-actions", "gitlab-ci")
	Type string `json:"type" yaml:"type"`

	// Config contains the provider-specific configuration.
	// The structure depends on the Type field.
	Config json.RawMessage `json:"config" yaml:"config"`
}

// LoadProvidersFromFile loads provider configurations from a YAML or JSON file.
// The file format is detected automatically based on the file extension.
func LoadProvidersFromFile(ctx context.Context, path string) (*Registry, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse based on file extension
	ext := filepath.Ext(path)
	var config ProvidersConfig

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s (use .yaml, .yml, or .json)", ext)
	}

	// Create registry and instantiate providers
	return LoadProvidersFromConfig(ctx, &config)
}

// LoadProvidersFromConfig creates a registry from parsed configuration.
func LoadProvidersFromConfig(ctx context.Context, config *ProvidersConfig) (*Registry, error) {
	registry := NewRegistry()

	for i, entry := range config.Providers {
		provider, err := createProvider(ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider at index %d: %w", i, err)
		}

		if err := registry.Register(provider); err != nil {
			return nil, fmt.Errorf("failed to register provider %q: %w", entry.Type, err)
		}
	}

	if len(registry.providers) == 0 {
		return nil, fmt.Errorf("no providers were loaded from configuration")
	}

	return registry, nil
}

// createProvider instantiates the appropriate provider based on the type field.
func createProvider(ctx context.Context, entry ProviderConfigEntry) (Provider, error) {
	switch entry.Type {
	case "github-actions":
		var config GitHubActionsConfig
		if err := json.Unmarshal(entry.Config, &config); err != nil {
			return nil, fmt.Errorf("failed to parse GitHub Actions config: %w", err)
		}
		return NewGitHubActionsProvider(ctx, config)

	// Future providers can be added here:
	// case "gitlab-ci":
	//     var config GitLabCIConfig
	//     if err := json.Unmarshal(entry.Config, &config); err != nil {
	//         return nil, fmt.Errorf("failed to parse GitLab CI config: %w", err)
	//     }
	//     return NewGitLabCIProvider(ctx, config)

	default:
		return nil, fmt.Errorf("unknown provider type: %q", entry.Type)
	}
}

// DefaultGitHubActionsConfig returns a sensible default configuration for GitHub Actions.
// Suitable for development and testing.
func DefaultGitHubActionsConfig(audience string) GitHubActionsConfig {
	return GitHubActionsConfig{
		ProviderConfig: ProviderConfig{
			Name:                "github-actions",
			IssuerURL:           "https://token.actions.githubusercontent.com",
			Audience:            audience,
			CertificateValidity: 5 * time.Minute,
			Enabled:             true,
		},
		AllowedRepositories:  nil, // Allow all repositories
		AllowedWorkflows:     nil, // Allow all workflows
		RequireRefProtection: false,
	}
}

// ExampleConfig returns an example configuration file content for documentation.
func ExampleConfig() string {
	return `# Signet OIDC Providers Configuration
# This file defines which identity providers can issue bridge certificates.

providers:
  # GitHub Actions OIDC provider
  - type: github-actions
    config:
      name: github-actions
      issuer_url: https://token.actions.githubusercontent.com
      audience: https://signet-authority.example.com
      certificate_validity: 5m
      enabled: true

      # Optional: Restrict to specific repositories
      # allowed_repositories:
      #   - jamestexas/signet
      #   - acme/production-app

      # Optional: Restrict to specific workflows
      # allowed_workflows:
      #   - .github/workflows/release.yml
      #   - .github/workflows/deploy.yml

      # Optional: Require protected refs (prevents PR from forks)
      # require_ref_protection: true

  # Future providers can be added here:
  # - type: gitlab-ci
  #   config:
  #     name: gitlab-ci
  #     issuer_url: https://gitlab.com
  #     audience: https://signet-authority.example.com
  #     certificate_validity: 5m
  #     enabled: true

  # - type: aws-iam
  #   config:
  #     name: aws-iam
  #     issuer_url: https://oidc.eks.us-west-2.amazonaws.com
  #     audience: sts.amazonaws.com
  #     certificate_validity: 5m
  #     enabled: true
`
}

// ValidateProvidersConfig checks if a providers configuration is valid.
// This can be used to validate configuration files before deployment.
func ValidateProvidersConfig(ctx context.Context, config *ProvidersConfig) error {
	if len(config.Providers) == 0 {
		return fmt.Errorf("no providers configured")
	}

	// Check for duplicate provider names
	names := make(map[string]bool)
	for i, entry := range config.Providers {
		if entry.Type == "" {
			return fmt.Errorf("provider at index %d is missing 'type' field", i)
		}

		// Try to create provider to validate configuration
		provider, err := createProvider(ctx, entry)
		if err != nil {
			return fmt.Errorf("provider at index %d: %w", i, err)
		}

		// Check for duplicate names
		name := provider.Name()
		if names[name] {
			return fmt.Errorf("duplicate provider name: %q", name)
		}
		names[name] = true
	}

	return nil
}

// LoadProvidersFromEnv loads provider configurations from environment variables.
// This is useful for containerized deployments where config files may not be available.
//
// Environment variables:
//
//	SIGNET_OIDC_PROVIDERS - JSON-encoded ProvidersConfig
//	SIGNET_GITHUB_ACTIONS_ENABLED - Enable GitHub Actions provider (default: false)
//	SIGNET_GITHUB_ACTIONS_AUDIENCE - Audience for GitHub Actions tokens
//	SIGNET_GITHUB_ACTIONS_ALLOWED_REPOS - Comma-separated list of allowed repositories
func LoadProvidersFromEnv(ctx context.Context) (*Registry, error) {
	// Check for explicit JSON config
	if providersJSON := os.Getenv("SIGNET_OIDC_PROVIDERS"); providersJSON != "" {
		var config ProvidersConfig
		if err := json.Unmarshal([]byte(providersJSON), &config); err != nil {
			return nil, fmt.Errorf("failed to parse SIGNET_OIDC_PROVIDERS: %w", err)
		}
		return LoadProvidersFromConfig(ctx, &config)
	}

	// Otherwise, build config from individual environment variables
	registry := NewRegistry()

	// GitHub Actions provider
	if os.Getenv("SIGNET_GITHUB_ACTIONS_ENABLED") == "true" {
		audience := os.Getenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")
		if audience == "" {
			return nil, fmt.Errorf("SIGNET_GITHUB_ACTIONS_AUDIENCE is required when GitHub Actions is enabled")
		}

		config := DefaultGitHubActionsConfig(audience)

		// Parse allowed repositories (if specified)
		if repos := os.Getenv("SIGNET_GITHUB_ACTIONS_ALLOWED_REPOS"); repos != "" {
			// Split comma-separated list
			// Simple implementation; production code would handle quoted values, escaping, etc.
			config.AllowedRepositories = splitTrimEmpty(repos, ",")
		}

		provider, err := NewGitHubActionsProvider(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub Actions provider: %w", err)
		}

		if err := registry.Register(provider); err != nil {
			return nil, fmt.Errorf("failed to register GitHub Actions provider: %w", err)
		}
	}

	// Future: Add other providers from environment variables

	if len(registry.providers) == 0 {
		return nil, fmt.Errorf("no providers enabled via environment variables")
	}

	return registry, nil
}

// splitTrimEmpty splits a string by a separator and trims whitespace from each part.
// Empty parts are excluded from the result.
func splitTrimEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}

	parts := []string{}
	for _, part := range splitByRune(s, rune(sep[0])) {
		if trimmed := trimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitByRune splits a string by a rune separator.
func splitByRune(s string, sep rune) []string {
	parts := []string{}
	start := 0
	for i, r := range s {
		if r == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// trimSpace removes leading and trailing whitespace from a string.
func trimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < end && isSpace(s[start]) {
		start++
	}

	// Trim trailing whitespace
	for end > start && isSpace(s[end-1]) {
		end--
	}

	return s[start:end]
}

// isSpace checks if a byte is a whitespace character.
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
