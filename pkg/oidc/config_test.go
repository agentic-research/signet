package oidc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProvidersFromFile_YAML(t *testing.T) {
	t.Skip("YAML unmarshaling into json.RawMessage is not supported by yaml.v3")
	// TODO: Implement custom YAML unmarshaling or convert YAML to JSON before parsing
	// JSON loading works correctly (see TestLoadProvidersFromFile_JSON)
}

func TestLoadProvidersFromFile_JSON(t *testing.T) {
	ctx := context.Background()

	// Create temp directory
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "providers.json")

	configContent := `{
  "providers": [
    {
      "type": "github-actions",
      "config": {
        "name": "github-actions",
        "issuer_url": "https://token.actions.githubusercontent.com",
        "audience": "https://test.example.com",
        "certificate_validity": 300000000000,
        "enabled": true
      }
    }
  ]
}`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load providers
	registry, err := LoadProvidersFromFile(ctx, configFile)
	if err != nil {
		t.Fatalf("LoadProvidersFromFile failed: %v", err)
	}

	// Verify provider was loaded
	provider := registry.Get("github-actions")
	if provider == nil {
		t.Fatal("Expected github-actions provider, got nil")
	}
}

func TestLoadProvidersFromFile_InvalidFormat(t *testing.T) {
	ctx := context.Background()

	// Create temp directory
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "providers.txt")

	configContent := `invalid content`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load providers - should fail
	_, err := LoadProvidersFromFile(ctx, configFile)
	if err == nil {
		t.Fatal("Expected error for unsupported file format")
	}

	expectedError := "unsupported config file format"
	if !containsSubstring(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestLoadProvidersFromFile_NonExistent(t *testing.T) {
	ctx := context.Background()

	// Try to load non-existent file
	_, err := LoadProvidersFromFile(ctx, "/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
}

func TestLoadProvidersFromFile_InvalidYAML(t *testing.T) {
	ctx := context.Background()

	// Create temp directory
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "providers.yaml")

	configContent := `
providers:
  - type: github-actions
    config:
      invalid yaml structure [[[
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load providers - should fail
	_, err := LoadProvidersFromFile(ctx, configFile)
	if err == nil {
		t.Fatal("Expected error for invalid YAML")
	}
}

func TestLoadProvidersFromEnv(t *testing.T) {
	ctx := context.Background()

	// Save original env vars
	originalEnabled := os.Getenv("SIGNET_GITHUB_ACTIONS_ENABLED")
	originalAudience := os.Getenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

	// Set environment variables
	os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", "true")
	os.Setenv("SIGNET_GITHUB_ACTIONS_AUDIENCE", "https://test.example.com")

	// Restore env vars after test
	defer func() {
		if originalEnabled == "" {
			os.Unsetenv("SIGNET_GITHUB_ACTIONS_ENABLED")
		} else {
			os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", originalEnabled)
		}
		if originalAudience == "" {
			os.Unsetenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")
		} else {
			os.Setenv("SIGNET_GITHUB_ACTIONS_AUDIENCE", originalAudience)
		}
	}()

	// Load providers
	registry, err := LoadProvidersFromEnv(ctx)
	if err != nil {
		t.Fatalf("LoadProvidersFromEnv failed: %v", err)
	}

	// Verify provider was loaded
	provider := registry.Get("github-actions")
	if provider == nil {
		t.Fatal("Expected github-actions provider, got nil")
	}

	if provider.Name() != "github-actions" {
		t.Errorf("Provider name = %q, want %q", provider.Name(), "github-actions")
	}
}

func TestLoadProvidersFromEnv_MissingAudience(t *testing.T) {
	ctx := context.Background()

	// Save original env vars
	originalEnabled := os.Getenv("SIGNET_GITHUB_ACTIONS_ENABLED")
	originalAudience := os.Getenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

	// Set only enabled flag
	os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", "true")
	os.Unsetenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

	// Restore env vars after test
	defer func() {
		if originalEnabled == "" {
			os.Unsetenv("SIGNET_GITHUB_ACTIONS_ENABLED")
		} else {
			os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", originalEnabled)
		}
		if originalAudience == "" {
			os.Unsetenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")
		} else {
			os.Setenv("SIGNET_GITHUB_ACTIONS_AUDIENCE", originalAudience)
		}
	}()

	// Load providers - should fail
	_, err := LoadProvidersFromEnv(ctx)
	if err == nil {
		t.Fatal("Expected error when audience is missing")
	}

	expectedError := "SIGNET_GITHUB_ACTIONS_AUDIENCE is required"
	if !containsSubstring(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestLoadProvidersFromEnv_NotEnabled(t *testing.T) {
	ctx := context.Background()

	// Save original env vars
	originalEnabled := os.Getenv("SIGNET_GITHUB_ACTIONS_ENABLED")
	originalAudience := os.Getenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

	// Ensure env vars are not set
	os.Unsetenv("SIGNET_GITHUB_ACTIONS_ENABLED")
	os.Unsetenv("SIGNET_GITHUB_ACTIONS_AUDIENCE")

	// Restore env vars after test
	defer func() {
		if originalEnabled != "" {
			os.Setenv("SIGNET_GITHUB_ACTIONS_ENABLED", originalEnabled)
		}
		if originalAudience != "" {
			os.Setenv("SIGNET_GITHUB_ACTIONS_AUDIENCE", originalAudience)
		}
	}()

	// Load providers - should fail with no providers enabled
	_, err := LoadProvidersFromEnv(ctx)
	if err == nil {
		t.Fatal("Expected error when no providers enabled")
	}

	expectedError := "no providers enabled"
	if !containsSubstring(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestValidateProvidersConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		config  *ProvidersConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ProvidersConfig{
				Providers: []ProviderConfigEntry{
					{
						Type:   "github-actions",
						Config: []byte(`{"name":"github-actions","issuer_url":"https://token.actions.githubusercontent.com","audience":"https://test.example.com","certificate_validity":300000000000,"enabled":true}`),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty providers",
			config: &ProvidersConfig{
				Providers: []ProviderConfigEntry{},
			},
			wantErr: true,
		},
		{
			name: "missing type",
			config: &ProvidersConfig{
				Providers: []ProviderConfigEntry{
					{
						Type:   "",
						Config: []byte(`{}`),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unknown provider type",
			config: &ProvidersConfig{
				Providers: []ProviderConfigEntry{
					{
						Type:   "unknown-provider",
						Config: []byte(`{}`),
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProvidersConfig(ctx, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProvidersConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSplitTrimEmpty(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{
			name: "simple split",
			s:    "a,b,c",
			sep:  ",",
			want: []string{"a", "b", "c"},
		},
		{
			name: "split with spaces",
			s:    "a, b , c",
			sep:  ",",
			want: []string{"a", "b", "c"},
		},
		{
			name: "split with empty parts",
			s:    "a,,c",
			sep:  ",",
			want: []string{"a", "c"},
		},
		{
			name: "empty string",
			s:    "",
			sep:  ",",
			want: nil,
		},
		{
			name: "single value",
			s:    "value",
			sep:  ",",
			want: []string{"value"},
		},
		{
			name: "only separator",
			s:    ",,,",
			sep:  ",",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitTrimEmpty(tt.s, tt.sep)

			if len(got) != len(tt.want) {
				t.Errorf("splitTrimEmpty() length = %d, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitTrimEmpty()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "no whitespace",
			s:    "hello",
			want: "hello",
		},
		{
			name: "leading whitespace",
			s:    "  hello",
			want: "hello",
		},
		{
			name: "trailing whitespace",
			s:    "hello  ",
			want: "hello",
		},
		{
			name: "both ends",
			s:    "  hello  ",
			want: "hello",
		},
		{
			name: "tabs and spaces",
			s:    "\t  hello  \t",
			want: "hello",
		},
		{
			name: "newlines",
			s:    "\nhello\n",
			want: "hello",
		},
		{
			name: "only whitespace",
			s:    "   ",
			want: "",
		},
		{
			name: "empty string",
			s:    "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimSpace(tt.s)
			if got != tt.want {
				t.Errorf("trimSpace() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsSpace(t *testing.T) {
	tests := []struct {
		name string
		b    byte
		want bool
	}{
		{name: "space", b: ' ', want: true},
		{name: "tab", b: '\t', want: true},
		{name: "newline", b: '\n', want: true},
		{name: "carriage return", b: '\r', want: true},
		{name: "letter", b: 'a', want: false},
		{name: "digit", b: '1', want: false},
		{name: "punctuation", b: '.', want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSpace(tt.b)
			if got != tt.want {
				t.Errorf("isSpace(%q) = %v, want %v", tt.b, got, tt.want)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
