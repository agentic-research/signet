package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jamestexas/signet/pkg/cli/styles"
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
	if homeDir != "" {
		absPath, err := filepath.Abs(homeDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" invalid home directory: %v\n", err)
			os.Exit(1)
		}
		homeDir = absPath
	}
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" %v\n", err)
		os.Exit(1)
	}
}
