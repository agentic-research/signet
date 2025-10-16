# OIDC Provider Pattern

**Status:** Implemented
**Version:** 1.0
**Date:** 2025-10-16

## Overview

The OIDC Provider Pattern enables Signet to support multiple identity platforms (GitHub Actions, GitLab CI, AWS, GCP, Azure) through a pluggable abstraction layer. Each provider translates platform-specific OIDC tokens into Signet bridge certificates with appropriate capabilities.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                        Authority                            │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Provider Registry                     │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │    │
│  │  │   GitHub     │  │   GitLab     │  │   AWS   │ │    │
│  │  │   Actions    │  │      CI      │  │   IAM   │ │    │
│  │  └──────────────┘  └──────────────┘  └─────────┘ │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ OIDC Token
                           │
                  ┌────────┴────────┐
                  │   CI/CD         │
                  │   Platform      │
                  └─────────────────┘
```

### Core Interface

```go
type Provider interface {
    // Name returns unique identifier (e.g., "github-actions")
    Name() string

    // Verify validates OIDC token and returns normalized claims
    Verify(ctx context.Context, rawToken string) (*Claims, error)

    // MapCapabilities converts claims to Signet capability URIs
    MapCapabilities(claims *Claims) ([]string, error)

    // ValidateConfig checks provider configuration
    ValidateConfig() error
}
```

### Provider Lifecycle

1. **Configuration Loading**
   - Load from YAML/JSON file or environment variables
   - Parse provider-specific configuration
   - Create provider instances

2. **Registration**
   - Validate provider configuration
   - Register in central registry
   - Make available for token verification

3. **Token Verification**
   - Receive OIDC token from CI/CD platform
   - Route to appropriate provider
   - Extract and normalize claims

4. **Capability Mapping**
   - Convert platform-specific claims to capabilities
   - Follow capability URI format (urn:signet:cap:{action}:{resource})
   - Return list of granted capabilities

5. **Bridge Certificate Issuance**
   - Create X.509 certificate with capabilities
   - Bind to ephemeral key from requestor
   - Set expiration (default: 5 minutes)

## Implementing a New Provider

### Step 1: Define Provider-Specific Claims

```go
// Example: GitLab CI claims
type GitLabCIClaims struct {
    ProjectPath     string `json:"project_path"`      // "owner/project"
    Ref             string `json:"ref"`               // "refs/heads/main"
    PipelineSource  string `json:"pipeline_source"`   // "push", "merge_request"
    RunnerID        string `json:"runner_id"`
    SHA             string `json:"sha"`
}
```

### Step 2: Implement Provider Interface

```go
type GitLabCIProvider struct {
    *BaseProvider
    config GitLabCIConfig
}

func (p *GitLabCIProvider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
    // 1. Use BaseProvider to verify token signature
    idToken, err := p.VerifyTokenInternal(ctx, rawToken)
    if err != nil {
        return nil, err
    }

    // 2. Extract GitLab-specific claims
    var glClaims GitLabCIClaims
    if err := idToken.Claims(&glClaims); err != nil {
        return nil, err
    }

    // 3. Validate GitLab-specific requirements
    if err := p.validateGitLabClaims(&glClaims); err != nil {
        return nil, err
    }

    // 4. Convert to normalized Claims
    return &Claims{
        Subject:  idToken.Subject,
        Issuer:   idToken.Issuer,
        Audience: idToken.Audience,
        Extra: map[string]interface{}{
            "project_path":    glClaims.ProjectPath,
            "ref":             glClaims.Ref,
            "pipeline_source": glClaims.PipelineSource,
            "runner_id":       glClaims.RunnerID,
            "sha":             glClaims.SHA,
        },
    }, nil
}

func (p *GitLabCIProvider) MapCapabilities(claims *Claims) ([]string, error) {
    projectPath := claims.Extra["project_path"].(string)
    return []string{
        fmt.Sprintf("urn:signet:cap:write:project:gitlab.com/%s", projectPath),
        fmt.Sprintf("urn:signet:cap:read:project:gitlab.com/%s", projectPath),
    }, nil
}
```

### Step 3: Add to Config System

```go
// In pkg/oidc/config.go
func createProvider(ctx context.Context, entry ProviderConfigEntry) (Provider, error) {
    switch entry.Type {
    case "github-actions":
        // existing code...

    case "gitlab-ci":  // Add new provider
        var config GitLabCIConfig
        if err := json.Unmarshal(entry.Config, &config); err != nil {
            return nil, fmt.Errorf("failed to parse GitLab CI config: %w", err)
        }
        return NewGitLabCIProvider(ctx, config)

    // ...
    }
}
```

### Step 4: Update Example Config

```yaml
# docs/examples/oidc-providers.yaml
providers:
  - type: gitlab-ci
    config:
      name: gitlab-ci
      issuer_url: https://gitlab.com
      audience: https://signet-authority.example.com
      certificate_validity: 5m
      enabled: true
```

## Configuration

### File-Based Configuration

```yaml
# oidc-providers.yaml
providers:
  - type: github-actions
    config:
      name: github-actions
      issuer_url: https://token.actions.githubusercontent.com
      audience: https://signet-authority.example.com
      certificate_validity: 5m
      enabled: true

      # Provider-specific options
      allowed_repositories:
        - jamestexas/signet
      allowed_workflows:
        - .github/workflows/release.yml
      require_ref_protection: false
```

Load with:

```go
registry, err := oidc.LoadProvidersFromFile(ctx, "oidc-providers.yaml")
```

### Environment Variable Configuration

```bash
# Enable GitHub Actions provider
export SIGNET_GITHUB_ACTIONS_ENABLED=true
export SIGNET_GITHUB_ACTIONS_AUDIENCE=https://signet-authority.example.com
export SIGNET_GITHUB_ACTIONS_ALLOWED_REPOS=jamestexas/signet,acme/app
```

Load with:

```go
registry, err := oidc.LoadProvidersFromEnv(ctx)
```

### Programmatic Configuration

```go
// Create provider directly
config := oidc.DefaultGitHubActionsConfig("https://signet-authority.example.com")
provider, err := oidc.NewGitHubActionsProvider(ctx, config)

// Create registry and register
registry := oidc.NewRegistry()
err = registry.Register(provider)
```

## Capability URI Format

Capabilities follow the format defined in `docs/design/004-bridge-certs.md`:

```
urn:signet:cap:{action}:{resource}[:{constraint}*]
```

### Examples by Provider

**GitHub Actions:**
```
urn:signet:cap:write:repo:github.com/jamestexas/signet
urn:signet:cap:read:repo:github.com/jamestexas/signet
urn:signet:cap:workflow:github.com/jamestexas/signet:.github/workflows/release.yml
```

**GitLab CI:**
```
urn:signet:cap:write:project:gitlab.com/acme/widget
urn:signet:cap:read:project:gitlab.com/acme/widget
urn:signet:cap:pipeline:gitlab.com/acme/widget:12345
```

**AWS IAM:**
```
urn:signet:cap:assume:role:aws:arn:aws:iam::123456789012:role/MyRole
urn:signet:cap:invoke:lambda:aws:arn:aws:lambda:us-west-2:123456789012:function:MyFunction
```

## Security Considerations

### Token Validation

All providers MUST:
1. Verify token signature using OIDC discovery
2. Check `iss` (issuer) matches expected value
3. Check `aud` (audience) matches authority URL
4. Check `exp` (expiration) is not in the past
5. Validate provider-specific claims

### Capability Scoping

Providers SHOULD:
1. Map claims to minimum necessary capabilities
2. Validate claim values before capability generation
3. Reject tokens with suspicious or malformed claims
4. Log capability grants for audit trails

### Configuration Validation

Providers MUST:
1. Validate configuration at startup
2. Fail fast on misconfiguration
3. Reject duplicate provider registrations
4. Sanitize user-provided configuration values

## Testing

### Unit Tests

Test each provider implementation:

```go
func TestGitHubActionsProvider_Verify(t *testing.T) {
    // Test valid token
    // Test expired token
    // Test wrong issuer
    // Test missing claims
    // Test allowed/disallowed repositories
}

func TestGitHubActionsProvider_MapCapabilities(t *testing.T) {
    // Test repository capability generation
    // Test workflow capability generation
    // Test missing claims handling
}
```

### Integration Tests

Test full workflow:

```go
func TestGitHubActionsIntegration(t *testing.T) {
    // 1. Create provider with config
    // 2. Load mock OIDC token
    // 3. Verify token
    // 4. Map capabilities
    // 5. Assert expected capabilities
}
```

## Usage Examples

### Authority Server

```go
// Load providers from config
registry, err := oidc.LoadProvidersFromFile(ctx, "oidc-providers.yaml")
if err != nil {
    log.Fatal(err)
}

// Verify token (auto-detects provider)
provider, claims, err := registry.VerifyToken(ctx, oidcToken)
if err != nil {
    return fmt.Errorf("token verification failed: %w", err)
}

// Map to capabilities
capabilities, err := provider.MapCapabilities(claims)
if err != nil {
    return fmt.Errorf("capability mapping failed: %w", err)
}

// Issue bridge certificate
cert := issueBridgeCert(ephemeralKey, capabilities, claims)
```

### CLI Client

```go
// Exchange OIDC token for bridge certificate
cmd := &cobra.Command{
    Use:   "exchange-token",
    Short: "Exchange OIDC token for bridge certificate",
    RunE: func(cmd *cobra.Command, args []string) error {
        // Read token from stdin or flag
        token := readOIDCToken()

        // Send to authority
        cert, err := exchangeOIDCToken(authorityURL, token)
        if err != nil {
            return err
        }

        // Save bridge certificate
        return saveBridgeCert(cert)
    },
}
```

## Future Providers

Planned provider implementations:

- **GitLab CI** - GitLab.com and self-hosted
- **AWS IAM** - EKS, Lambda, EC2 instance roles
- **GCP Workload Identity** - GKE, Cloud Run, Cloud Functions
- **Azure Managed Identity** - AKS, Azure Functions, VMs
- **CircleCI OIDC** - CircleCI workflows
- **Buildkite OIDC** - Buildkite pipelines

## References

- **Bridge Certificates**: `docs/design/004-bridge-certs.md`
- **OIDC Specification**: https://openid.net/specs/openid-connect-core-1_0.html
- **GitHub Actions OIDC**: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- **go-oidc Library**: https://github.com/coreos/go-oidc

## Changelog

### v1.0 (2025-10-16)

- Initial OIDC provider abstraction
- GitHub Actions provider implementation
- Registry and configuration system
- Example configurations and workflows
- Documentation

---

*Enabling secret-free CI/CD through pluggable OIDC identity providers*
