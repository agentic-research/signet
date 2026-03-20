package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SECURITY: Regex for validating GitHub repository format
// GitHub repository names: owner/repo where both parts can contain alphanumeric, dash, underscore, dot
// This prevents injection attacks via malicious repository claims
var githubRepoRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$`)

// GitHubActionsProvider implements the Provider interface for GitHub Actions OIDC tokens.
// GitHub Actions provides ambient OIDC credentials via ACTIONS_ID_TOKEN_REQUEST_URL
// and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables.
//
// Token claims reference: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
type GitHubActionsProvider struct {
	*BaseProvider
	config GitHubActionsConfig
}

// GitHubActionsConfig extends ProviderConfig with GitHub-specific settings.
type GitHubActionsConfig struct {
	ProviderConfig

	// AllowedRepositories restricts which repositories can get bridge certificates.
	// Empty list = allow all repositories. Useful for self-hosted authority servers
	// that only serve specific organizations/repositories.
	// Format: "owner/repo" (e.g., "agentic-research/signet")
	AllowedRepositories []string `json:"allowed_repositories" yaml:"allowed_repositories"`

	// AllowedWorkflows restricts which workflow files can get bridge certificates.
	// Empty list = allow all workflows.
	// Format: relative path (e.g., ".github/workflows/release.yml")
	AllowedWorkflows []string `json:"allowed_workflows" yaml:"allowed_workflows"`

	// RequireRefProtection requires the ref to be a protected branch or tag.
	// Prevents bridge certificates from being issued for PRs from forks.
	// When enabled, only refs matching refs/heads/* and refs/tags/* are allowed;
	// refs matching refs/pull/* are explicitly denied.
	RequireRefProtection bool `json:"require_ref_protection" yaml:"require_ref_protection"`

	// ProtectedBranches restricts which branches are allowed when RequireRefProtection is enabled.
	// If non-empty, only branches whose name (without the refs/heads/ prefix) appears in this
	// list are permitted. Tags (refs/tags/*) are always allowed regardless of this setting.
	// If empty, all refs/heads/* and refs/tags/* refs are allowed.
	// Example: ["main", "master"]
	ProtectedBranches []string `json:"protected_branches,omitempty" yaml:"protected_branches,omitempty"`
}

// GitHubActionsClaims represents GitHub Actions-specific OIDC token claims.
// Reference: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
type GitHubActionsClaims struct {
	// Repository is the owner/repo (e.g., "agentic-research/signet")
	Repository string `json:"repository"`

	// Ref is the git ref that triggered the workflow (e.g., "refs/heads/main")
	Ref string `json:"ref"`

	// SHA is the commit SHA that triggered the workflow
	SHA string `json:"sha"`

	// Workflow is the workflow file path (e.g., ".github/workflows/release.yml")
	Workflow string `json:"workflow"`

	// Actor is the GitHub username that triggered the workflow
	Actor string `json:"actor"`

	// JobWorkflowRef is the full ref including workflow file
	// Format: "owner/repo/.github/workflows/file.yml@refs/heads/main"
	JobWorkflowRef string `json:"job_workflow_ref"`

	// RepositoryOwner is the repository owner (e.g., "agentic-research")
	RepositoryOwner string `json:"repository_owner"`

	// RepositoryOwnerID is the owner's numeric GitHub ID
	RepositoryOwnerID string `json:"repository_owner_id"`

	// RunID is the unique workflow run ID
	RunID string `json:"run_id"`

	// RunNumber is the workflow run number
	RunNumber string `json:"run_number"`

	// RunAttempt is the attempt number for this run (for re-runs)
	RunAttempt string `json:"run_attempt"`

	// JTI is the unique token identifier for replay prevention.
	// If not present in the raw JWT, synthesized from run_id + run_attempt.
	JTI string `json:"jti"`
}

// NewGitHubActionsProvider creates a new GitHub Actions OIDC provider.
func NewGitHubActionsProvider(ctx context.Context, config GitHubActionsConfig) (*GitHubActionsProvider, error) {
	// Set provider-specific defaults
	if config.Name == "" {
		config.Name = "github-actions"
	}
	if config.IssuerURL == "" {
		config.IssuerURL = "https://token.actions.githubusercontent.com"
	}

	base, err := NewBaseProvider(ctx, config.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base provider: %w", err)
	}

	return &GitHubActionsProvider{
		BaseProvider: base,
		config:       config,
	}, nil
}

// Name returns the provider's unique identifier.
func (p *GitHubActionsProvider) Name() string {
	return p.config.Name
}

// Verify validates a GitHub Actions OIDC token and returns normalized claims.
func (p *GitHubActionsProvider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	// Use base provider to verify token signature and standard claims
	idToken, err := p.VerifyTokenInternal(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract GitHub Actions-specific claims
	var ghClaims GitHubActionsClaims
	if err := idToken.Claims(&ghClaims); err != nil {
		return nil, fmt.Errorf("failed to extract GitHub Actions claims: %w", err)
	}

	// Validate GitHub-specific requirements
	if err := p.validateGitHubClaims(&ghClaims); err != nil {
		return nil, fmt.Errorf("GitHub claims validation failed: %w", err)
	}

	// Ensure JTI exists for replay prevention.
	// GHA tokens may include jti in standard claims. If absent, synthesize
	// one from a SHA-256 hash of the raw token. This is unique per-token
	// (unlike run_id+run_attempt which can have multiple tokens per run).
	jti := ghClaims.JTI
	if jti == "" {
		h := sha256.Sum256([]byte(rawToken))
		jti = "gha-" + hex.EncodeToString(h[:16]) // 32 hex chars, prefixed
	}

	// Convert to normalized Claims structure
	claims := &Claims{
		Subject:   idToken.Subject,
		Issuer:    idToken.Issuer,
		Audience:  idToken.Audience,
		ExpiresAt: idToken.Expiry,
		IssuedAt:  idToken.IssuedAt,
		Extra: map[string]interface{}{
			"jti":                 jti,
			"repository":          ghClaims.Repository,
			"ref":                 ghClaims.Ref,
			"sha":                 ghClaims.SHA,
			"workflow":            ghClaims.Workflow,
			"actor":               ghClaims.Actor,
			"job_workflow_ref":    ghClaims.JobWorkflowRef,
			"repository_owner":    ghClaims.RepositoryOwner,
			"repository_owner_id": ghClaims.RepositoryOwnerID,
			"run_id":              ghClaims.RunID,
			"run_number":          ghClaims.RunNumber,
			"run_attempt":         ghClaims.RunAttempt,
		},
	}

	return claims, nil
}

// validateGitHubClaims checks GitHub-specific claim requirements.
func (p *GitHubActionsProvider) validateGitHubClaims(claims *GitHubActionsClaims) error {
	// Repository claim is required
	if claims.Repository == "" {
		return fmt.Errorf("repository claim is missing")
	}

	// Check allowed repositories (if configured)
	if len(p.config.AllowedRepositories) > 0 {
		allowed := false
		for _, repo := range p.config.AllowedRepositories {
			if claims.Repository == repo {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("repository %q is not in allowed list", claims.Repository)
		}
	}

	// Check allowed workflows (if configured)
	if len(p.config.AllowedWorkflows) > 0 {
		allowed := false
		for _, workflow := range p.config.AllowedWorkflows {
			if claims.Workflow == workflow {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("workflow %q is not in allowed list", claims.Workflow)
		}
	}

	// Check ref protection (if required)
	if p.config.RequireRefProtection {
		if claims.Ref == "" {
			return fmt.Errorf("ref claim is required when ref protection is enabled")
		}

		// Explicitly deny pull request refs (PRs from forks)
		if strings.HasPrefix(claims.Ref, "refs/pull/") {
			return fmt.Errorf("pull request refs are not allowed when ref protection is enabled: %q", claims.Ref)
		}

		// Only allow branch and tag refs
		isBranch := strings.HasPrefix(claims.Ref, "refs/heads/")
		isTag := strings.HasPrefix(claims.Ref, "refs/tags/")
		if !isBranch && !isTag {
			return fmt.Errorf("ref %q is not a branch or tag ref", claims.Ref)
		}

		// If ProtectedBranches is set, verify the branch is in the allow list.
		// Tags are always allowed regardless of ProtectedBranches.
		if isBranch && len(p.config.ProtectedBranches) > 0 {
			branchName := strings.TrimPrefix(claims.Ref, "refs/heads/")
			allowed := false
			for _, pb := range p.config.ProtectedBranches {
				if branchName == pb {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("branch %q is not in the protected branches list", branchName)
			}
		}
	}

	return nil
}

// MapCapabilities converts GitHub Actions claims into Signet capability URIs.
// Per docs/design/004-bridge-certs.md, capabilities follow the pattern:
// urn:signet:cap:{action}:{resource}
//
// SECURITY FIX #8: Validates repository format and URL-escapes to prevent injection.
func (p *GitHubActionsProvider) MapCapabilities(claims *Claims) ([]string, error) {
	repository, ok := claims.Extra["repository"].(string)
	if !ok || repository == "" {
		return nil, fmt.Errorf("repository claim is required for capability mapping")
	}

	// SECURITY FIX #8: Validate repository format before using in capability URIs
	if !githubRepoRegex.MatchString(repository) {
		return nil, fmt.Errorf("invalid repository format: %q", repository)
	}

	// SECURITY FIX #8: URL-escape repository name to prevent injection attacks
	safeRepo := url.PathEscape(repository)

	// Generate repository write capability
	// Format: urn:signet:cap:write:repo:github.com/{owner}/{repo}
	capabilities := []string{
		fmt.Sprintf("urn:signet:cap:write:repo:github.com/%s", safeRepo),
	}

	// Optional: Add read capability (could be used for verification)
	capabilities = append(capabilities,
		fmt.Sprintf("urn:signet:cap:read:repo:github.com/%s", safeRepo),
	)

	// Optional: Add workflow-specific capability for audit trails
	if workflow, ok := claims.Extra["workflow"].(string); ok && workflow != "" {
		// Validate and escape workflow path as well
		safeWorkflow := url.PathEscape(workflow)
		capabilities = append(capabilities,
			fmt.Sprintf("urn:signet:cap:workflow:github.com/%s:%s", safeRepo, safeWorkflow),
		)
	}

	return capabilities, nil
}

// ValidateConfig checks if the GitHub Actions provider configuration is valid.
func (p *GitHubActionsProvider) ValidateConfig() error {
	// Validate base configuration
	if err := p.BaseProvider.ValidateConfig(); err != nil {
		return err
	}

	// Validate GitHub-specific configuration
	if p.config.IssuerURL != "https://token.actions.githubusercontent.com" {
		return fmt.Errorf("GitHub Actions issuer URL must be https://token.actions.githubusercontent.com")
	}

	// Validate allowed repositories format (if specified)
	for _, repo := range p.config.AllowedRepositories {
		if repo == "" {
			return fmt.Errorf("allowed repository cannot be empty")
		}
		// Basic format validation: should be "owner/repo"
		// A more robust implementation would validate against GitHub's naming rules
	}

	// Validate allowed workflows format (if specified)
	for _, workflow := range p.config.AllowedWorkflows {
		if workflow == "" {
			return fmt.Errorf("allowed workflow cannot be empty")
		}
		// Basic format validation: should start with .github/workflows/
		// A more robust implementation would validate path format
	}

	return nil
}

// GetGitHubClaims is a helper to extract typed GitHub claims from normalized Claims.
// This is useful when the authority needs access to GitHub-specific information.
func GetGitHubClaims(claims *Claims) (*GitHubActionsClaims, error) {
	if claims.Extra == nil {
		return nil, fmt.Errorf("no extra claims found")
	}

	ghClaims := &GitHubActionsClaims{}

	// Helper to extract string claim
	getString := func(key string) (string, error) {
		val, ok := claims.Extra[key]
		if !ok {
			return "", fmt.Errorf("claim %q not found", key)
		}
		str, ok := val.(string)
		if !ok {
			return "", fmt.Errorf("claim %q is not a string", key)
		}
		return str, nil
	}

	var err error
	if ghClaims.Repository, err = getString("repository"); err != nil {
		return nil, fmt.Errorf("failed to validate GitHub claim %q: %w", "repository", err)
	}
	if ghClaims.Ref, err = getString("ref"); err != nil {
		return nil, fmt.Errorf("failed to validate GitHub claim %q: %w", "ref", err)
	}
	if ghClaims.SHA, err = getString("sha"); err != nil {
		return nil, fmt.Errorf("failed to validate GitHub claim %q: %w", "sha", err)
	}
	if ghClaims.Workflow, err = getString("workflow"); err != nil {
		return nil, fmt.Errorf("failed to validate GitHub claim %q: %w", "workflow", err)
	}
	if ghClaims.Actor, err = getString("actor"); err != nil {
		return nil, fmt.Errorf("failed to validate GitHub claim %q: %w", "actor", err)
	}

	// Optional claims (may not be present in all tokens)
	ghClaims.JobWorkflowRef, _ = getString("job_workflow_ref")
	ghClaims.RepositoryOwner, _ = getString("repository_owner")
	ghClaims.RepositoryOwnerID, _ = getString("repository_owner_id")
	ghClaims.RunID, _ = getString("run_id")
	ghClaims.RunNumber, _ = getString("run_number")
	ghClaims.RunAttempt, _ = getString("run_attempt")
	ghClaims.JTI, _ = getString("jti")

	return ghClaims, nil
}
