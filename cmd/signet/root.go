package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jamestexas/signet/pkg/cli/config"
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
		// Convert to absolute path first
		absPath, err := filepath.Abs(homeDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" invalid home directory: %v\n", err)
			os.Exit(1)
		}

		// Clean the path to resolve any .. or . elements
		cleanPath := filepath.Clean(absPath)

		// Ensure the path is not trying to access system directories
		// Block access to root, /etc, /usr, /bin, /sbin, /var, /sys, /proc
		systemPaths := []string{"/", "/etc", "/usr", "/bin", "/sbin", "/var", "/sys", "/proc"}
		for _, sysPath := range systemPaths {
			if cleanPath == sysPath || strings.HasPrefix(cleanPath, sysPath+string(filepath.Separator)) {
				fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" home directory cannot be in system path: %s\n", cleanPath)
				os.Exit(1)
			}
		}

		// Also check that the path doesn't contain any symbolic links that could
		// lead to path traversal attacks
		evalPath, err := filepath.EvalSymlinks(cleanPath)
		if err == nil {
			// Path exists, check if evaluated path is different (indicating symlinks)
			if evalPath != cleanPath {
				// Re-check the evaluated path against system directories
				for _, sysPath := range systemPaths {
					if evalPath == sysPath || strings.HasPrefix(evalPath, sysPath+string(filepath.Separator)) {
						fmt.Fprintf(os.Stderr, styles.Error.Render("✗")+" home directory symlink resolves to system path: %s\n", evalPath)
						os.Exit(1)
					}
				}
				cleanPath = evalPath
			}
		}
		// If EvalSymlinks fails because path doesn't exist yet, that's okay

		homeDir = cleanPath
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
