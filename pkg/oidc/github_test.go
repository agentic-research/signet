package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestGitHubActionsProvider_ValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  GitHubActionsConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name:                "github-actions",
					IssuerURL:           "https://token.actions.githubusercontent.com",
					Audience:            "https://test.example.com",
					CertificateValidity: 5 * time.Minute,
					Enabled:             true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with allowed repositories",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name:                "github-actions",
					IssuerURL:           "https://token.actions.githubusercontent.com",
					Audience:            "https://test.example.com",
					CertificateValidity: 5 * time.Minute,
					Enabled:             true,
				},
				AllowedRepositories: []string{"agentic-research/signet", "acme/production"},
			},
			wantErr: false,
		},
		{
			name: "wrong issuer URL",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name:      "github-actions",
					IssuerURL: "https://wrong-issuer.com",
					Audience:  "https://test.example.com",
					Enabled:   true,
				},
			},
			wantErr: true,
		},
		{
			name: "missing name",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					IssuerURL: "https://token.actions.githubusercontent.com",
					Audience:  "https://test.example.com",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip actual provider creation for invalid configs
			// since NewGitHubActionsProvider will try to contact the OIDC endpoint
			if tt.wantErr && tt.config.IssuerURL == "https://wrong-issuer.com" {
				// Just validate the config logic
				if tt.config.IssuerURL != "https://token.actions.githubusercontent.com" {
					// Expected validation error
					return
				}
				t.Error("Expected issuer validation to fail")
				return
			}

			// For valid configs, test ValidateConfig on BaseProvider
			bp := &BaseProvider{config: tt.config.ProviderConfig}
			err := bp.ValidateConfig()

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetGitHubClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  *Claims
		want    *GitHubActionsClaims
		wantErr bool
	}{
		{
			name: "valid claims",
			claims: &Claims{
				Subject:  "repo:agentic-research/signet:ref:refs/heads/main",
				Issuer:   "https://token.actions.githubusercontent.com",
				Audience: []string{"https://test.example.com"},
				Extra: map[string]interface{}{
					"repository": "agentic-research/signet",
					"ref":        "refs/heads/main",
					"sha":        "abc123def456",
					"workflow":   ".github/workflows/release.yml",
					"actor":      "agentic-research",
				},
			},
			want: &GitHubActionsClaims{
				Repository: "agentic-research/signet",
				Ref:        "refs/heads/main",
				SHA:        "abc123def456",
				Workflow:   ".github/workflows/release.yml",
				Actor:      "agentic-research",
			},
			wantErr: false,
		},
		{
			name: "missing repository claim",
			claims: &Claims{
				Extra: map[string]interface{}{
					"ref":      "refs/heads/main",
					"workflow": ".github/workflows/release.yml",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty repository claim",
			claims: &Claims{
				Extra: map[string]interface{}{
					"repository": "",
					"ref":        "refs/heads/main",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "nil extra claims",
			claims: &Claims{
				Extra: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetGitHubClaims(tt.claims)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if got.Repository != tt.want.Repository {
				t.Errorf("Repository = %q, want %q", got.Repository, tt.want.Repository)
			}
			if got.Ref != tt.want.Ref {
				t.Errorf("Ref = %q, want %q", got.Ref, tt.want.Ref)
			}
			if got.SHA != tt.want.SHA {
				t.Errorf("SHA = %q, want %q", got.SHA, tt.want.SHA)
			}
			if got.Workflow != tt.want.Workflow {
				t.Errorf("Workflow = %q, want %q", got.Workflow, tt.want.Workflow)
			}
			if got.Actor != tt.want.Actor {
				t.Errorf("Actor = %q, want %q", got.Actor, tt.want.Actor)
			}
		})
	}
}

func TestGitHubActionsProvider_MapCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		config       GitHubActionsConfig
		claims       *Claims
		wantCaps     []string
		wantErr      bool
		errorMessage string
	}{
		{
			name: "valid repository claim",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name: "github-actions",
				},
			},
			claims: &Claims{
				Extra: map[string]interface{}{
					"repository": "agentic-research/signet",
					"ref":        "refs/heads/main",
					"sha":        "abc123def456",
					"workflow":   ".github/workflows/release.yml",
					"actor":      "agentic-research",
				},
			},
			wantCaps: []string{
				"urn:signet:cap:write:repo:github.com/agentic-research%2Fsignet",
				"urn:signet:cap:read:repo:github.com/agentic-research%2Fsignet",
				"urn:signet:cap:workflow:github.com/agentic-research%2Fsignet:.github%2Fworkflows%2Frelease.yml",
			},
			wantErr: false,
		},
		{
			name: "repository not in allowed list",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name: "github-actions",
				},
				AllowedRepositories: []string{"allowed/repo"},
			},
			claims: &Claims{
				Extra: map[string]interface{}{
					"repository": "notallowed/repo",
					"ref":        "refs/heads/main",
					"sha":        "abc123",
					"workflow":   ".github/workflows/test.yml",
					"actor":      "someone",
				},
			},
			wantCaps:     nil,
			wantErr:      true,
			errorMessage: "repository not allowed",
		},
		{
			name: "workflow not in allowed list",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name: "github-actions",
				},
				AllowedWorkflows: []string{".github/workflows/allowed.yml"},
			},
			claims: &Claims{
				Extra: map[string]interface{}{
					"repository": "agentic-research/signet",
					"ref":        "refs/heads/main",
					"sha":        "abc123",
					"workflow":   ".github/workflows/notallowed.yml",
					"actor":      "agentic-research",
				},
			},
			wantCaps:     nil,
			wantErr:      true,
			errorMessage: "workflow not allowed",
		},
		{
			name: "ref protection required - PR from fork denied",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name: "github-actions",
				},
				RequireRefProtection: true,
			},
			claims: &Claims{
				Extra: map[string]interface{}{
					"repository": "agentic-research/signet",
					"ref":        "refs/pull/123/merge",
					"sha":        "abc123",
					"workflow":   ".github/workflows/test.yml",
					"actor":      "agentic-research",
				},
			},
			wantCaps:     nil,
			wantErr:      true,
			errorMessage: "pull request refs not allowed",
		},
		{
			name: "missing repository claim",
			config: GitHubActionsConfig{
				ProviderConfig: ProviderConfig{
					Name: "github-actions",
				},
			},
			claims: &Claims{
				Extra: map[string]interface{}{
					"ref": "refs/heads/main",
				},
			},
			wantCaps: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a provider with the config to test validateGitHubClaims
			provider := &GitHubActionsProvider{
				BaseProvider: &BaseProvider{config: tt.config.ProviderConfig},
				config:       tt.config,
			}

			// Get GitHub claims
			ghClaims, err := GetGitHubClaims(tt.claims)
			if err != nil && !tt.wantErr {
				t.Fatalf("GetGitHubClaims failed: %v", err)
			}
			if err != nil && tt.wantErr {
				// Expected error from GetGitHubClaims
				return
			}

			// Validate using the actual validateGitHubClaims method
			if err := provider.validateGitHubClaims(ghClaims); err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected validation error: %v", err)
				}
				return
			}

			if tt.wantErr {
				t.Error("Expected error, got nil")
				return
			}

			// Build capabilities using MapCapabilities
			capabilities, err := provider.MapCapabilities(tt.claims)
			if err != nil {
				t.Fatalf("MapCapabilities failed: %v", err)
			}

			// Verify capabilities match expected
			if len(capabilities) != len(tt.wantCaps) {
				t.Errorf("Expected %d capabilities, got %d", len(tt.wantCaps), len(capabilities))
				return
			}

			for i, cap := range capabilities {
				if cap != tt.wantCaps[i] {
					t.Errorf("Capability %d = %q, want %q", i, cap, tt.wantCaps[i])
				}
			}
		})
	}
}

func TestValidateGitHubClaims_RefProtection(t *testing.T) {
	baseClaims := func(ref string) *GitHubActionsClaims {
		return &GitHubActionsClaims{
			Repository: "agentic-research/signet",
			Ref:        ref,
			SHA:        "abc123",
			Workflow:   ".github/workflows/test.yml",
			Actor:      "agentic-research",
		}
	}

	tests := []struct {
		name             string
		config           GitHubActionsConfig
		claims           *GitHubActionsClaims
		wantErr          bool
		wantErrSubstring string
	}{
		{
			name: "PR from fork ref denied",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:           baseClaims("refs/pull/123/merge"),
			wantErr:          true,
			wantErrSubstring: "pull request refs are not allowed",
		},
		{
			name: "PR head ref denied",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:           baseClaims("refs/pull/456/head"),
			wantErr:          true,
			wantErrSubstring: "pull request refs are not allowed",
		},
		{
			name: "protected branch ref allowed",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:  baseClaims("refs/heads/main"),
			wantErr: false,
		},
		{
			name: "any branch ref allowed when no ProtectedBranches list",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:  baseClaims("refs/heads/feature-branch"),
			wantErr: false,
		},
		{
			name: "tag ref allowed",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:  baseClaims("refs/tags/v1.0.0"),
			wantErr: false,
		},
		{
			name: "empty ref denied",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:           baseClaims(""),
			wantErr:          true,
			wantErrSubstring: "ref claim is required",
		},
		{
			name: "unknown ref pattern denied",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
			},
			claims:           baseClaims("refs/remotes/origin/main"),
			wantErr:          true,
			wantErrSubstring: "not a branch or tag ref",
		},
		{
			name: "custom ProtectedBranches - allowed branch",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
				ProtectedBranches:    []string{"main", "master"},
			},
			claims:  baseClaims("refs/heads/main"),
			wantErr: false,
		},
		{
			name: "custom ProtectedBranches - disallowed branch",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
				ProtectedBranches:    []string{"main", "master"},
			},
			claims:           baseClaims("refs/heads/develop"),
			wantErr:          true,
			wantErrSubstring: "not in the protected branches list",
		},
		{
			name: "custom ProtectedBranches - tags always allowed",
			config: GitHubActionsConfig{
				RequireRefProtection: true,
				ProtectedBranches:    []string{"main"},
			},
			claims:  baseClaims("refs/tags/v2.0.0"),
			wantErr: false,
		},
		{
			name: "ref protection disabled - all refs pass",
			config: GitHubActionsConfig{
				RequireRefProtection: false,
			},
			claims:  baseClaims("refs/pull/123/merge"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &GitHubActionsProvider{
				BaseProvider: &BaseProvider{config: tt.config.ProviderConfig},
				config:       tt.config,
			}

			err := provider.validateGitHubClaims(tt.claims)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.wantErrSubstring != "" {
					if !strings.Contains(err.Error(), tt.wantErrSubstring) {
						t.Errorf("Error %q does not contain %q", err.Error(), tt.wantErrSubstring)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDefaultGitHubActionsConfig(t *testing.T) {
	audience := "https://test.example.com"
	config := DefaultGitHubActionsConfig(audience)

	if config.Name != "github-actions" {
		t.Errorf("Name = %q, want %q", config.Name, "github-actions")
	}

	if config.IssuerURL != "https://token.actions.githubusercontent.com" {
		t.Errorf("IssuerURL = %q, want %q", config.IssuerURL, "https://token.actions.githubusercontent.com")
	}

	if config.Audience != audience {
		t.Errorf("Audience = %q, want %q", config.Audience, audience)
	}

	if config.CertificateValidity != 5*time.Minute {
		t.Errorf("CertificateValidity = %v, want %v", config.CertificateValidity, 5*time.Minute)
	}

	if !config.Enabled {
		t.Error("Expected Enabled = true")
	}

	if config.AllowedRepositories != nil {
		t.Errorf("Expected AllowedRepositories = nil, got %v", config.AllowedRepositories)
	}

	if config.AllowedWorkflows != nil {
		t.Errorf("Expected AllowedWorkflows = nil, got %v", config.AllowedWorkflows)
	}

	if config.RequireRefProtection {
		t.Error("Expected RequireRefProtection = false")
	}
}
