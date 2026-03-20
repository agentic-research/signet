package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
)

// SECURITY: Regex for validating email format (simple but sufficient for capability URIs).
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// CloudflareAccessProvider implements the Provider interface for Cloudflare Access JWTs.
// Cloudflare Access issues OIDC tokens for authenticated users via Access policies.
//
// Token claims reference: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/application-token/
type CloudflareAccessProvider struct {
	*BaseProvider
	config CloudflareAccessConfig
}

// CloudflareAccessConfig extends ProviderConfig with Cloudflare Access-specific settings.
type CloudflareAccessConfig struct {
	ProviderConfig

	// TeamDomain is the Cloudflare Access team name (e.g., "myteam").
	// Used to construct the issuer URL: https://<TeamDomain>.cloudflareaccess.com
	TeamDomain string `json:"team_domain" yaml:"team_domain"`

	// AllowedEmails restricts which email addresses can get bridge certificates.
	// Empty list = allow all authenticated emails.
	AllowedEmails []string `json:"allowed_emails" yaml:"allowed_emails"`
}

// CloudflareAccessClaims represents Cloudflare Access-specific OIDC token claims.
type CloudflareAccessClaims struct {
	// Email is the authenticated user's email address.
	Email string `json:"email"`

	// Sub is the subject identifier (user ID within CF Access).
	Sub string `json:"sub"`

	// IdentityNonce is a unique nonce per authentication session.
	IdentityNonce string `json:"identity_nonce"`
}

// NewCloudflareAccessProvider creates a new Cloudflare Access OIDC provider.
func NewCloudflareAccessProvider(ctx context.Context, config CloudflareAccessConfig) (*CloudflareAccessProvider, error) {
	if config.Name == "" {
		config.Name = "cloudflare-access"
	}
	if config.TeamDomain != "" && config.IssuerURL == "" {
		config.IssuerURL = fmt.Sprintf("https://%s.cloudflareaccess.com", config.TeamDomain)
	}

	base, err := NewBaseProvider(ctx, config.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base provider: %w", err)
	}

	return &CloudflareAccessProvider{
		BaseProvider: base,
		config:       config,
	}, nil
}

// Name returns the provider's unique identifier.
func (p *CloudflareAccessProvider) Name() string {
	return p.config.Name
}

// Verify validates a Cloudflare Access OIDC token and returns normalized claims.
func (p *CloudflareAccessProvider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := p.VerifyTokenInternal(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	var cfClaims CloudflareAccessClaims
	if err := idToken.Claims(&cfClaims); err != nil {
		return nil, fmt.Errorf("failed to extract Cloudflare Access claims: %w", err)
	}

	if err := p.validateClaims(&cfClaims); err != nil {
		return nil, fmt.Errorf("Cloudflare Access claims validation failed: %w", err)
	}

	// Synthesize JTI from token hash if identity_nonce is absent.
	jti := cfClaims.IdentityNonce
	if jti == "" {
		h := sha256.Sum256([]byte(rawToken))
		jti = "cfa-" + hex.EncodeToString(h[:16])
	}

	claims := &Claims{
		Subject:   idToken.Subject,
		Issuer:    idToken.Issuer,
		Audience:  idToken.Audience,
		ExpiresAt: idToken.Expiry,
		IssuedAt:  idToken.IssuedAt,
		Extra: map[string]any{
			"jti":            jti,
			"email":          cfClaims.Email,
			"identity_nonce": cfClaims.IdentityNonce,
		},
	}

	return claims, nil
}

// validateClaims checks Cloudflare Access-specific claim requirements.
func (p *CloudflareAccessProvider) validateClaims(claims *CloudflareAccessClaims) error {
	if claims.Email == "" {
		return fmt.Errorf("email claim is missing")
	}

	if len(p.config.AllowedEmails) > 0 {
		if !slices.Contains(p.config.AllowedEmails, claims.Email) {
			return fmt.Errorf("email %q is not in allowed list", claims.Email)
		}
	}

	return nil
}

// MapCapabilities converts Cloudflare Access claims into Signet capability URIs.
// Maps email to: urn:signet:cap:mcp:rosary.bot/<email>
//
// SECURITY: Validates email format and URL-escapes to prevent injection.
func (p *CloudflareAccessProvider) MapCapabilities(claims *Claims) ([]string, error) {
	email, ok := claims.Extra["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("email claim is required for capability mapping")
	}

	if !emailRegex.MatchString(email) {
		return nil, fmt.Errorf("invalid email format: %q", email)
	}

	safeEmail := url.PathEscape(email)

	capabilities := []string{
		fmt.Sprintf("urn:signet:cap:mcp:rosary.bot/%s", safeEmail),
	}

	return capabilities, nil
}

// ValidateConfig checks if the Cloudflare Access provider configuration is valid.
func (p *CloudflareAccessProvider) ValidateConfig() error {
	if err := p.BaseProvider.ValidateConfig(); err != nil {
		return err
	}

	if p.config.TeamDomain == "" {
		return fmt.Errorf("team_domain is required for Cloudflare Access provider")
	}

	expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", p.config.TeamDomain)
	if p.config.IssuerURL != expectedIssuer {
		return fmt.Errorf("issuer URL must be %s", expectedIssuer)
	}

	for _, email := range p.config.AllowedEmails {
		if email == "" {
			return fmt.Errorf("allowed email cannot be empty")
		}
	}

	return nil
}
