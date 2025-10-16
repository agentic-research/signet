package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockProvider implements Provider interface for testing
type mockProvider struct {
	name             string
	verifyCalled     bool
	verifyError      error
	capabilitiesFunc func(*Claims) ([]string, error)
	validateError    error
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	m.verifyCalled = true
	if m.verifyError != nil {
		return nil, m.verifyError
	}
	return &Claims{
		Subject:   "test-subject",
		Issuer:    "test-issuer",
		Audience:  []string{"test-audience"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		Extra:     map[string]interface{}{"test": "value"},
	}, nil
}

func (m *mockProvider) MapCapabilities(claims *Claims) ([]string, error) {
	if m.capabilitiesFunc != nil {
		return m.capabilitiesFunc(claims)
	}
	return []string{"urn:signet:cap:test:resource"}, nil
}

func (m *mockProvider) ValidateConfig() error {
	return m.validateError
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()

	// Create mock provider
	provider := &mockProvider{name: "test"}

	// Register should succeed
	err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Duplicate registration should fail
	err = registry.Register(provider)
	if err == nil {
		t.Fatal("Expected error for duplicate registration")
	}

	expectedError := "provider \"test\" already registered"
	if err.Error() != expectedError {
		t.Errorf("Expected error %q, got %q", expectedError, err.Error())
	}
}

func TestRegistry_Register_ValidationFailure(t *testing.T) {
	registry := NewRegistry()

	// Create provider that fails validation
	provider := &mockProvider{
		name:          "invalid",
		validateError: errors.New("validation failed"),
	}

	// Register should fail
	err := registry.Register(provider)
	if err == nil {
		t.Fatal("Expected error for invalid provider")
	}

	if !errors.Is(err, provider.validateError) {
		t.Errorf("Expected validation error to be wrapped")
	}
}

func TestRegistry_Get(t *testing.T) {
	registry := NewRegistry()
	provider := &mockProvider{name: "test"}
	if err := registry.Register(provider); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Get existing provider
	got := registry.Get("test")
	if got == nil {
		t.Fatal("Expected provider, got nil")
	}

	if got.Name() != "test" {
		t.Errorf("Expected provider name 'test', got %q", got.Name())
	}

	// Get non-existent provider
	got = registry.Get("nonexistent")
	if got != nil {
		t.Fatal("Expected nil, got provider")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()

	// Empty registry
	names := registry.List()
	if len(names) != 0 {
		t.Errorf("Expected 0 providers, got %d", len(names))
	}

	// Register providers
	if err := registry.Register(&mockProvider{name: "provider1"}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := registry.Register(&mockProvider{name: "provider2"}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	names = registry.List()
	if len(names) != 2 {
		t.Fatalf("Expected 2 providers, got %d", len(names))
	}

	// Verify both provider names are present
	nameMap := make(map[string]bool)
	for _, name := range names {
		nameMap[name] = true
	}

	if !nameMap["provider1"] || !nameMap["provider2"] {
		t.Errorf("Expected both provider1 and provider2, got %v", names)
	}
}

func TestRegistry_VerifyToken(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	// Empty registry should fail
	_, _, err := registry.VerifyToken(ctx, "test-token")
	if err == nil {
		t.Fatal("Expected error for empty registry")
	}

	// Register providers
	provider1 := &mockProvider{
		name:        "provider1",
		verifyError: errors.New("invalid token"),
	}
	provider2 := &mockProvider{
		name: "provider2",
		// No error - will succeed
	}

	if err := registry.Register(provider1); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := registry.Register(provider2); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify token - should try both providers and succeed with provider2
	provider, claims, err := registry.VerifyToken(ctx, "test-token")
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	// Should return provider2 since provider1 failed
	if provider.Name() != "provider2" {
		t.Errorf("Expected provider2, got %q", provider.Name())
	}

	if claims.Subject != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got %q", claims.Subject)
	}

	// Verify both providers were called
	if !provider1.verifyCalled {
		t.Error("Provider1 Verify was not called")
	}
	if !provider2.verifyCalled {
		t.Error("Provider2 Verify was not called")
	}
}

func TestRegistry_VerifyToken_AllFail(t *testing.T) {
	registry := NewRegistry()
	ctx := context.Background()

	// Register providers that all fail
	provider1 := &mockProvider{
		name:        "provider1",
		verifyError: errors.New("invalid token 1"),
	}
	provider2 := &mockProvider{
		name:        "provider2",
		verifyError: errors.New("invalid token 2"),
	}

	if err := registry.Register(provider1); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := registry.Register(provider2); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify token - should fail with all providers
	_, _, err := registry.VerifyToken(ctx, "test-token")
	if err == nil {
		t.Fatal("Expected error when all providers fail")
	}

	expectedError := "no provider could verify token"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestBaseProvider_ValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ProviderConfig{
				Name:                "test",
				IssuerURL:           "https://issuer.example.com",
				Audience:            "https://audience.example.com",
				CertificateValidity: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			config: ProviderConfig{
				IssuerURL: "https://issuer.example.com",
				Audience:  "https://audience.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing issuer URL",
			config: ProviderConfig{
				Name:     "test",
				Audience: "https://audience.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			config: ProviderConfig{
				Name:      "test",
				IssuerURL: "https://issuer.example.com",
			},
			wantErr: true,
		},
		{
			name: "zero validity defaults to 5 minutes",
			config: ProviderConfig{
				Name:      "test",
				IssuerURL: "https://issuer.example.com",
				Audience:  "https://audience.example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := &BaseProvider{config: tt.config}
			err := bp.ValidateConfig()

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify default validity was set
				if tt.config.CertificateValidity == 0 {
					if bp.config.CertificateValidity != 5*time.Minute {
						t.Errorf("Expected default validity 5m, got %v", bp.config.CertificateValidity)
					}
				}
			}
		})
	}
}

func TestBaseProvider_Config(t *testing.T) {
	config := ProviderConfig{
		Name:                "test",
		IssuerURL:           "https://issuer.example.com",
		Audience:            "https://audience.example.com",
		CertificateValidity: 5 * time.Minute,
	}

	bp := &BaseProvider{config: config}
	got := bp.Config()

	if got.Name != config.Name {
		t.Errorf("Expected name %q, got %q", config.Name, got.Name)
	}
	if got.IssuerURL != config.IssuerURL {
		t.Errorf("Expected issuer URL %q, got %q", config.IssuerURL, got.IssuerURL)
	}
	if got.Audience != config.Audience {
		t.Errorf("Expected audience %q, got %q", config.Audience, got.Audience)
	}
	if got.CertificateValidity != config.CertificateValidity {
		t.Errorf("Expected validity %v, got %v", config.CertificateValidity, got.CertificateValidity)
	}
}
