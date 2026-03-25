package authflow

import (
	"crypto/ed25519"
	"log/slog"

	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
	"github.com/agentic-research/signet/pkg/policy"
)

// Deps holds shared infrastructure that all flows need.
// Passed to FlowFactory during construction. This is a plain struct (not an
// interface) because all flows need the same concrete dependencies.
type Deps struct {
	// CA is the local certificate authority for minting bridge certs.
	CA *attestx509.LocalCA

	// PublicKey is the authority's Ed25519 trust anchor (for policy bundle verification).
	PublicKey ed25519.PublicKey

	// Logger is the structured logger.
	Logger *slog.Logger

	// PolicyEvaluator handles CI/CD-specific allowlists (repos, workflows).
	PolicyEvaluator policy.PolicyEvaluator

	// PolicyChecker handles trust policy bundle verification (ADR-011).
	PolicyChecker *policy.PolicyChecker

	// ProviderRegistry holds OIDC providers for token verification.
	// Nil if no CI/CD providers are configured.
	ProviderRegistry *oidcprovider.Registry

	// Config contains flow-relevant configuration extracted from AuthorityConfig.
	Config *FlowConfig
}

// FlowConfig contains configuration fields that flows need.
// Extracted from AuthorityConfig to avoid leaking CLI concerns into the package.
type FlowConfig struct {
	// CertificateValidity is the default cert lifetime in hours.
	CertificateValidity int

	// MaxCertValidityHours is the hard cap on cert lifetime.
	MaxCertValidityHours int

	// SessionSecret is used for browser flow session encryption (AES-256-GCM).
	SessionSecret string

	// RedirectURL is the OAuth2 callback URL for browser flow.
	RedirectURL string

	// OIDCProviderURL is the OIDC discovery URL.
	OIDCProviderURL string

	// OIDCClientID is the OAuth2 client ID.
	OIDCClientID string

	// OIDCClientSecret is the OAuth2 client secret.
	OIDCClientSecret string

	// TrustedProxyHeader for client IP extraction (e.g., "CF-Connecting-IP").
	TrustedProxyHeader string
}
