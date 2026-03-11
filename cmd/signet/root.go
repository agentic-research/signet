package main

import (
	"fmt"
	"os"

	"github.com/agentic-research/signet/pkg/cli/config"
	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	homeDir string
	debug   bool
)

var rootCmd = &cobra.Command{
	Use:   "signet",
	Short: "Signet - Offline cryptographic signing",
	Long: `Signet is an offline-first cryptographic authentication protocol.
It replaces bearer tokens with ephemeral proof-of-possession signatures
using a machine-as-identity model.`,
	Version: "1.0.0-alpha",
}

func init() {
	// Global persistent flags available to all subcommands
	rootCmd.PersistentFlags().StringVar(&homeDir, "home", "", "Signet home directory (default: ~/.signet)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")
	cobra.OnInitialize(initConfig)
}

// initConfig sanitizes and validates global flags.
func initConfig() {
	cfg := getConfig()
	if err := cfg.ValidateHomePathRuntime(); err != nil {
		fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" invalid home directory: %v\n", err)
		os.Exit(1)
	}
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" %v\n", err)
		os.Exit(1)
	}
}

// getConfig loads configuration with flag overrides
func getConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		// Fallback to default config
		cfg = config.New(config.DefaultHome())
	}

	// Override with --home flag if provided
	if homeDir != "" {
		cfg.Home = homeDir
	}

	return cfg
}
