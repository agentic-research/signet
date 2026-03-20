package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestCloudflareAccessProvider_ValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  CloudflareAccessConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: CloudflareAccessConfig{
				ProviderConfig: ProviderConfig{
					Name:                "cloudflare-access",
					IssuerURL:           "https://myteam.cloudflareaccess.com",
					Audience:            "https://test.example.com",
					CertificateValidity: 5 * time.Minute,
					Enabled:             true,
				},
				TeamDomain: "myteam",
			},
			wantErr: false,
		},
		{
			name: "valid config with allowed emails",
			config: CloudflareAccessConfig{
				ProviderConfig: ProviderConfig{
					Name:                "cloudflare-access",
					IssuerURL:           "https://myteam.cloudflareaccess.com",
					Audience:            "https://test.example.com",
					CertificateValidity: 5 * time.Minute,
					Enabled:             true,
				},
				TeamDomain:    "myteam",
				AllowedEmails: []string{"alice@example.com", "bob@example.com"},
			},
			wantErr: false,
		},
		{
			name: "missing team domain",
			config: CloudflareAccessConfig{
				ProviderConfig: ProviderConfig{
					Name:      "cloudflare-access",
					IssuerURL: "https://myteam.cloudflareaccess.com",
					Audience:  "https://test.example.com",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong issuer URL",
			config: CloudflareAccessConfig{
				ProviderConfig: ProviderConfig{
					Name:      "cloudflare-access",
					IssuerURL: "https://wrong.example.com",
					Audience:  "https://test.example.com",
				},
				TeamDomain: "myteam",
			},
			wantErr: true,
		},
		{
			name: "missing name",
			config: CloudflareAccessConfig{
				ProviderConfig: ProviderConfig{
					IssuerURL: "https://myteam.cloudflareaccess.com",
					Audience:  "https://test.example.com",
				},
				TeamDomain: "myteam",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &CloudflareAccessProvider{
				BaseProvider: &BaseProvider{config: tt.config.ProviderConfig},
				config:       tt.config,
			}
			err := provider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCloudflareAccessProvider_ValidateClaims(t *testing.T) {
	tests := []struct {
		name             string
		config           CloudflareAccessConfig
		claims           *CloudflareAccessClaims
		wantErr          bool
		wantErrSubstring string
	}{
		{
			name:   "valid email",
			config: CloudflareAccessConfig{},
			claims: &CloudflareAccessClaims{
				Email: "alice@example.com",
				Sub:   "user-123",
			},
			wantErr: false,
		},
		{
			name: "email in allowed list",
			config: CloudflareAccessConfig{
				AllowedEmails: []string{"alice@example.com", "bob@example.com"},
			},
			claims: &CloudflareAccessClaims{
				Email: "alice@example.com",
				Sub:   "user-123",
			},
			wantErr: false,
		},
		{
			name: "email not in allowed list",
			config: CloudflareAccessConfig{
				AllowedEmails: []string{"alice@example.com"},
			},
			claims: &CloudflareAccessClaims{
				Email: "eve@example.com",
				Sub:   "user-456",
			},
			wantErr:          true,
			wantErrSubstring: "not in allowed list",
		},
		{
			name:   "missing email",
			config: CloudflareAccessConfig{},
			claims: &CloudflareAccessClaims{
				Sub: "user-123",
			},
			wantErr:          true,
			wantErrSubstring: "email claim is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &CloudflareAccessProvider{
				BaseProvider: &BaseProvider{config: tt.config.ProviderConfig},
				config:       tt.config,
			}
			err := provider.validateClaims(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.wantErrSubstring != "" && !strings.Contains(err.Error(), tt.wantErrSubstring) {
					t.Errorf("Error %q does not contain %q", err.Error(), tt.wantErrSubstring)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCloudflareAccessProvider_MapCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		claims   *Claims
		wantCaps []string
		wantErr  bool
	}{
		{
			name: "valid email claim",
			claims: &Claims{
				Extra: map[string]any{
					"email":          "alice@example.com",
					"identity_nonce": "nonce-abc",
				},
			},
			wantCaps: []string{
				"urn:signet:cap:mcp:rosary.bot/alice@example.com",
			},
			wantErr: false,
		},
		{
			name: "missing email claim",
			claims: &Claims{
				Extra: map[string]any{
					"identity_nonce": "nonce-abc",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid email format",
			claims: &Claims{
				Extra: map[string]any{
					"email": "not-an-email",
				},
			},
			wantErr: true,
		},
		{
			name: "empty extra claims",
			claims: &Claims{
				Extra: map[string]any{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &CloudflareAccessProvider{
				BaseProvider: &BaseProvider{config: ProviderConfig{Name: "cloudflare-access"}},
				config:       CloudflareAccessConfig{TeamDomain: "myteam", CapabilityDomain: "rosary.bot"},
			}

			caps, err := provider.MapCapabilities(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(caps) != len(tt.wantCaps) {
				t.Fatalf("Expected %d capabilities, got %d", len(tt.wantCaps), len(caps))
			}
			for i, cap := range caps {
				if cap != tt.wantCaps[i] {
					t.Errorf("Capability %d = %q, want %q", i, cap, tt.wantCaps[i])
				}
			}
		})
	}
}

func TestCloudflareAccessProvider_Name(t *testing.T) {
	provider := &CloudflareAccessProvider{
		config: CloudflareAccessConfig{
			ProviderConfig: ProviderConfig{Name: "cloudflare-access"},
		},
	}
	if got := provider.Name(); got != "cloudflare-access" {
		t.Errorf("Name() = %q, want %q", got, "cloudflare-access")
	}
}
