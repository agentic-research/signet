package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/cli/styles"
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

	// Init subcommand flags
	initInsecureFlag bool
	forceFlag        bool

	// Signet config
	homeDir string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "signet-git",
		Short: "Git integration for Signet",
		Long: `signet-git provides Git commit signing using Signet's ephemeral certificates.

When called by Git (gpgsm-compatible mode):
  git config --global gpg.format x509
  git config --global gpg.x509.program signet-git
  git config --global user.signingKey $(signet-git export-key-id)

For initialization and key management, use the subcommands:
  signet-git init           # Initialize Signet keystore
  signet-git export-key-id  # Export master key ID for Git config`,
		RunE: runGitInterface,

		// This is the key to making the gpgsm interface work with subcommands.
		// When Git calls signet-git, it may pass unknown arguments.
		// Without this, Cobra sees an unknown arg and assumes it's a subcommand,
		// causing it to fail before executing the root command's RunE.
		// TraverseChildren tells Cobra to parse flags and execute the root RunE
		// even if unknown arguments are present.
		TraverseChildren: true,

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

	// Add subcommands
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(exportKeyIDCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Signet configuration",
		Long: `Initialize Signet by generating a master key and storing it securely.

By default, the master key is stored in the OS keyring (Keychain on macOS).
Use --insecure to store in a file instead (for testing only).`,
		Example: `  # Initialize with OS keyring (recommended)
  signet-git init

  # Initialize with file-based storage (testing only)
  signet-git init --insecure

  # Force re-initialization
  signet-git init --force`,
		RunE:          runInit,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&initInsecureFlag, "insecure", false, "Initialize with file-based storage (for testing)")
	cmd.Flags().BoolVar(&forceFlag, "force", false, "Force re-initialization (overwrites existing key)")

	return cmd
}

func exportKeyIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-key-id",
		Short: "Export the master key ID",
		Long: `Export the master key ID for Git configuration.

This command outputs the master key ID that should be used with:
  git config --global user.signingKey $(signet-git export-key-id)`,
		Example: `  # Export key ID
  signet-git export-key-id

  # Configure Git
  git config --global user.signingKey $(signet-git export-key-id)`,
		RunE:          runExportKeyID,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	// Get configuration
	cfg := getConfig()

	// Handle initialization
	if initInsecureFlag {
		if err := keystore.InitializeInsecure(cfg.Home, forceFlag); err != nil {
			return fmt.Errorf("insecure initialization failed: %w", err)
		}
		fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully (insecure file-based storage)")
	} else {
		if err := keystore.InitializeSecure(forceFlag); err != nil {
			return fmt.Errorf("initialization failed: %w", err)
		}
		fmt.Println(styles.Success.Render("✓") + " Signet initialized successfully")
	}
	return nil
}

func runExportKeyID(cmd *cobra.Command, args []string) error {
	cfg := getConfig()

	// Try secure keyring first
	keyID, err := keystore.GetKeyIDSecure()
	if err != nil {
		// Fallback to file-based
		keyID, err = keystore.GetKeyIDInsecure(cfg.Home)
		if err != nil {
			return fmt.Errorf("failed to get key ID: %w", err)
		}
	}
	// Output raw key ID for Git (no styling for machine-readable output)
	fmt.Println(keyID)
	return nil
}

func runGitInterface(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg := getConfig()

	// Determine operation mode
	if verifyFile != "" {
		// Verification mode: --verify <sigfile> <datafile|->
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
