package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Provider represents an OIDC identity provider that can issue bridge certificates.
// Implementations handle provider-specific token verification, claim extraction,
// and capability mapping for different platforms (GitHub Actions, GitLab CI, AWS, etc.)
type Provider interface {
	// Name returns the provider's unique identifier (e.g., "github-actions", "gitlab-ci")
	Name() string

	// Verify validates an OIDC token from this provider and returns standard claims.
	// Returns an error if the token is invalid, expired, or from wrong issuer.
	Verify(ctx context.Context, rawToken string) (*Claims, error)

	// MapCapabilities converts provider-specific claims into Signet capability URIs.
	// For example, GitHub's "repository" claim → "urn:signet:cap:write:repo:github.com/{repo}"
	MapCapabilities(claims *Claims) ([]string, error)

	// ValidateConfig checks if the provider's configuration is valid.
	// Called during initialization to fail fast on misconfiguration.
	ValidateConfig() error
}

// Claims represents normalized claims extracted from an OIDC token.
// Providers map their specific claim structure to this common format.
type Claims struct {
	// Standard OIDC claims
	Subject   string    `json:"sub"`           // Subject identifier (user/service ID)
	Issuer    string    `json:"iss"`           // Token issuer URL
	Audience  []string  `json:"aud"`           // Intended audience(s)
	ExpiresAt time.Time `json:"exp"`           // Token expiration time
	IssuedAt  time.Time `json:"iat"`           // Token issuance time
	NotBefore time.Time `json:"nbf,omitempty"` // Token validity start time

	// Provider-specific claims (stored as map for flexibility)
	// Examples:
	//   GitHub Actions: "repository", "ref", "workflow", "actor", "sha"
	//   GitLab CI: "project_path", "pipeline_source", "ref", "runner_id"
	//   AWS: "arn", "account", "assumed_role", "session_name"
	Extra map[string]interface{} `json:"extra"`
}

// ProviderConfig represents configuration for an OIDC provider.
// Each provider implementation can embed this and add provider-specific fields.
type ProviderConfig struct {
	// Name uniquely identifies this provider (e.g., "github-actions")
	Name string `json:"name" yaml:"name"`

	// IssuerURL is the OIDC discovery endpoint (e.g., "https://token.actions.githubusercontent.com")
	IssuerURL string `json:"issuer_url" yaml:"issuer_url"`

	// Audience is the expected "aud" claim value (typically the authority's URL)
	Audience string `json:"audience" yaml:"audience"`

	// CertificateValidity is the duration for bridge certificates issued for this provider.
	// Default: 5 minutes (per 004-bridge-certs.md design)
	CertificateValidity time.Duration `json:"certificate_validity" yaml:"certificate_validity"`

	// Enabled controls whether this provider is active.
	// Useful for disabling providers without removing config.
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// Registry manages multiple OIDC providers and routes tokens to the correct provider.
// Enables supporting multiple identity platforms simultaneously (GitHub + GitLab + AWS).
type Registry struct {
	providers map[string]Provider // Keyed by provider name
}

// NewRegistry creates a new empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider to the registry.
// Returns an error if a provider with the same name already exists.
func (r *Registry) Register(provider Provider) error {
	name := provider.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %q already registered", name)
	}

	// Validate provider configuration before registering
	if err := provider.ValidateConfig(); err != nil {
		return fmt.Errorf("provider %q configuration invalid: %w", name, err)
	}

	r.providers[name] = provider
	return nil
}

// Get retrieves a provider by name.
// Returns nil if the provider is not registered.
func (r *Registry) Get(name string) Provider {
	return r.providers[name]
}

// List returns all registered provider names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// VerifyToken attempts to verify a token against all registered providers.
// Returns the provider that successfully verified the token and the extracted claims.
// This is useful when the caller doesn't know which provider issued the token.
func (r *Registry) VerifyToken(ctx context.Context, rawToken string) (Provider, *Claims, error) {
	if len(r.providers) == 0 {
		return nil, nil, fmt.Errorf("no providers registered")
	}

	// Try each provider until one succeeds
	var lastErr error
	for name, provider := range r.providers {
		claims, err := provider.Verify(ctx, rawToken)
		if err == nil {
			return provider, claims, nil
		}
		lastErr = fmt.Errorf("provider %q: %w", name, err)
	}

	return nil, nil, fmt.Errorf("no provider could verify token: %w", lastErr)
}

// BaseProvider provides common OIDC verification functionality.
// Provider implementations can embed this to avoid duplicating verification logic.
type BaseProvider struct {
	config   ProviderConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// NewBaseProvider creates a new base provider with common OIDC verification setup.
func NewBaseProvider(ctx context.Context, config ProviderConfig) (*BaseProvider, error) {
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.Audience,
	})

	return &BaseProvider{
		config:   config,
		provider: provider,
		verifier: verifier,
	}, nil
}

// VerifyTokenInternal handles common OIDC token verification.
// Provider implementations call this and then extract provider-specific claims.
func (b *BaseProvider) VerifyTokenInternal(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	return b.verifier.Verify(ctx, rawToken)
}

// Config returns the provider's configuration.
func (b *BaseProvider) Config() ProviderConfig {
	return b.config
}

// ValidateConfig checks if the base provider configuration is valid.
func (b *BaseProvider) ValidateConfig() error {
	if b.config.Name == "" {
		return fmt.Errorf("provider name is required")
	}
	if b.config.IssuerURL == "" {
		return fmt.Errorf("issuer URL is required")
	}
	if b.config.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if b.config.CertificateValidity <= 0 {
		// Default to 5 minutes if not specified
		b.config.CertificateValidity = 5 * time.Minute
	}
	return nil
}
