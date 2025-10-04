package main

import (
	"os"

	"github.com/jamestexas/signet/pkg/cli/config"
)

// getConfig returns the configuration from flags, environment, or defaults
func getConfig() *config.Config {
	// Determine home directory
	home := homeDir
	if home == "" {
		if envHome := os.Getenv("SIGNET_HOME"); envHome != "" {
			home = envHome
		} else {
			home = config.DefaultHome()
		}
	}

	// Create config
	cfg := config.New(home)

	// Ensure home directory exists
	if err := cfg.EnsureHome(); err != nil && debug {
		// Log warning but don't fail
	}

	return cfg
}
