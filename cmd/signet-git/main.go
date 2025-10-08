package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/git"
)

var (
	// Git-compatible flags (gpgsm interface)
	signFlag       bool
	detachSignFlag bool
	armorFlag      bool
	localUser      string
	statusFd       int
	verifyFile     string

	// Signet config
	homeDir string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "signet-git",
		Short: "Git integration for Signet (gpgsm-compatible interface)",
		Long: `signet-git is a Git-specific interface for Signet that implements
the gpgsm-compatible protocol expected by Git when using x509 signing.

This binary is designed to be used as:
  git config --global gpg.x509.program signet-git
  git config --global gpg.format x509

For the full Signet CLI with subcommands, use 'signet' instead.`,
		RunE:          runGitInterface,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Git-compatible flags (gpgsm interface)
	rootCmd.Flags().BoolVarP(&signFlag, "sign", "s", false, "make a signature")
	rootCmd.Flags().BoolVarP(&detachSignFlag, "detach-sign", "b", false, "make a detached signature")
	rootCmd.Flags().BoolVarP(&armorFlag, "armor", "a", false, "create ascii armored output")
	rootCmd.Flags().StringVarP(&localUser, "local-user", "u", "", "use USER-ID to sign")
	rootCmd.Flags().IntVar(&statusFd, "status-fd", 0, "write special status strings to the file descriptor n")
	rootCmd.Flags().StringVar(&verifyFile, "verify", "", "verify a signature from file")

	// Signet-specific flags
	rootCmd.PersistentFlags().StringVar(&homeDir, "home", "", "signet home directory")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runGitInterface(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg := getConfig()

	// Determine operation mode
	if verifyFile != "" {
		// Verification mode: --verify <sigfile> <datafile|-}
		dataFile := ""
		if len(args) > 0 {
			dataFile = args[0]
		}
		return git.VerifySignature(cfg, verifyFile, dataFile, statusFd)
	}

	if signFlag || detachSignFlag {
		// Signing mode: read from stdin, write signature to stdout
		return git.SignCommit(cfg, localUser, statusFd)
	}

	// No operation specified, show help
	return cmd.Help()
}

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
