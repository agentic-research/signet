package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPersistence(t *testing.T) {
	tempHome := t.TempDir()
	
	t.Run("Save and Load config", func(t *testing.T) {
		cfg := New(tempHome)
		cfg.AuthEndpoint = "http://test-dashboard"
		cfg.MCPURL = "http://test-mcp"
		cfg.IssuerDID = "did:test:123"

		if err := cfg.Save(); err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}

		// Verify file exists
		configPath := filepath.Join(tempHome, "config.json")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Fatalf("Config file was not created at %s", configPath)
		}

		// Load in a fresh environment
		os.Setenv("SIGNET_HOME", tempHome)
		defer os.Unsetenv("SIGNET_HOME")

		loaded, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if loaded.AuthEndpoint != cfg.AuthEndpoint {
			t.Errorf("Expected AuthEndpoint %q, got %q", cfg.AuthEndpoint, loaded.AuthEndpoint)
		}
		if loaded.MCPURL != cfg.MCPURL {
			t.Errorf("Expected MCPURL %q, got %q", cfg.MCPURL, loaded.MCPURL)
		}
		if loaded.IssuerDID != cfg.IssuerDID {
			t.Errorf("Expected IssuerDID %q, got %q", cfg.IssuerDID, loaded.IssuerDID)
		}
	})

	t.Run("Environment variable precedence", func(t *testing.T) {
		cfg := New(tempHome)
		cfg.AuthEndpoint = "http://file-endpoint"
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}

		os.Setenv("SIGNET_HOME", tempHome)
		os.Setenv("SIGNET_AUTH_ENDPOINT", "http://env-endpoint")
		defer os.Unsetenv("SIGNET_HOME")
		defer os.Unsetenv("SIGNET_AUTH_ENDPOINT")

		loaded, err := Load()
		if err != nil {
			t.Fatal(err)
		}

		if loaded.AuthEndpoint != "http://env-endpoint" {
			t.Errorf("Env var should override file config. Expected 'http://env-endpoint', got %q", loaded.AuthEndpoint)
		}
	})
}
