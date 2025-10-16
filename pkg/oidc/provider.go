package oidc

import (
	"context"
	"fmt"
	"sync"
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
//
// SECURITY: Uses constant-time provider selection to prevent timing attacks.
// All providers are tried before returning to avoid leaking which providers are configured.
func (r *Registry) VerifyToken(ctx context.Context, rawToken string) (Provider, *Claims, error) {
	if len(r.providers) == 0 {
		return nil, nil, fmt.Errorf("no providers registered")
	}

	// SECURITY FIX #4: Try all providers without early return (constant-time)
	// This prevents timing attacks that could reveal which providers are configured
	type result struct {
		provider Provider
		claims   *Claims
		err      error
	}

	results := make([]result, 0, len(r.providers))

	// Try all providers (don't return early)
	for _, provider := range r.providers {
		claims, err := provider.Verify(ctx, rawToken)
		results = append(results, result{
			provider: provider,
			claims:   claims,
			err:      err,
		})
	}

	// Select first success after all attempts complete
	for _, res := range results {
		if res.err == nil {
			return res.provider, res.claims, nil
		}
	}

	return nil, nil, fmt.Errorf("no provider could verify token")
}

// Shutdown gracefully stops all registered providers.
// RESOURCE MANAGEMENT: Stops JWKS refresh goroutines to prevent leaks.
// Should be called during server shutdown to clean up resources.
func (r *Registry) Shutdown() {
	for _, provider := range r.providers {
		// Check if provider has a Stop() method (providers that embed BaseProvider)
		if stopper, ok := provider.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}
}

// BaseProvider provides common OIDC verification functionality.
// Provider implementations can embed this to avoid duplicating verification logic.
//
// SECURITY: Includes JWKS refresh mechanism to handle provider key rotation.
// If provider keys are compromised and rotated, the authority refreshes JWKS
// every hour instead of caching indefinitely.
type BaseProvider struct {
	config   ProviderConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier

	// SECURITY FIX #6: JWKS refresh support
	mu            sync.RWMutex       // Protects provider/verifier during refresh
	stopRefresh   chan struct{}      // Signals refresh goroutine to stop
	refreshCancel context.CancelFunc // Cancels JWKS refresh context
}

// NewBaseProvider creates a new base provider with common OIDC verification setup.
// SECURITY FIX #6: Starts JWKS refresh goroutine to handle provider key rotation.
// RESOURCE MANAGEMENT: Uses cancellable context to ensure HTTP requests stop on shutdown.
func NewBaseProvider(ctx context.Context, config ProviderConfig) (*BaseProvider, error) {
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.Audience,
	})

	// Create cancellable context for JWKS refresh goroutine
	refreshCtx, refreshCancel := context.WithCancel(context.Background())

	bp := &BaseProvider{
		config:        config,
		provider:      provider,
		verifier:      verifier,
		stopRefresh:   make(chan struct{}),
		refreshCancel: refreshCancel,
	}

	// Start JWKS refresh goroutine with cancellable context
	go bp.startJWKSRefresh(refreshCtx)

	return bp, nil
}

// startJWKSRefresh periodically refreshes the OIDC provider to get updated JWKS.
// SECURITY: If provider keys are compromised and rotated, this ensures the authority
// picks up new keys within 1 hour instead of caching them indefinitely.
func (b *BaseProvider) startJWKSRefresh(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Refresh OIDC provider (fetches new JWKS)
			newProvider, err := oidc.NewProvider(ctx, b.config.IssuerURL)
			if err != nil {
				// Log but don't crash - keep using existing provider
				// In production, this should be logged with proper logger
				continue
			}

			newVerifier := newProvider.Verifier(&oidc.Config{
				ClientID: b.config.Audience,
			})

			// Atomically update provider and verifier
			b.mu.Lock()
			b.provider = newProvider
			b.verifier = newVerifier
			b.mu.Unlock()

		case <-b.stopRefresh:
			return
		}
	}
}

// Stop stops the JWKS refresh goroutine.
// Should be called when shutting down the provider to avoid goroutine leaks.
// RESOURCE MANAGEMENT: Cancels context to stop in-flight HTTP requests immediately.
func (b *BaseProvider) Stop() {
	if b.refreshCancel != nil {
		b.refreshCancel() // Cancel any in-flight HTTP requests
	}
	close(b.stopRefresh)
}

// VerifyTokenInternal handles common OIDC token verification.
// Provider implementations call this and then extract provider-specific claims.
// SECURITY: Uses read lock to allow concurrent verification during JWKS refresh.
func (b *BaseProvider) VerifyTokenInternal(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
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
