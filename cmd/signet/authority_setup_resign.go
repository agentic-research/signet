package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/spf13/cobra"
)

var (
	setupResignRepo    string
	setupResignKeyFile string
	setupResignDryRun  bool
)

var setupResignCmd = &cobra.Command{
	Use:   "setup-resign",
	Short: "Configure GitHub Actions post-merge re-signing",
	Long: `Set up the Signet post-merge re-signing workflow for a GitHub repository.

This command automates the setup process:
  1. Generate (or reuse) a persistent Ed25519 master key
  2. Store the key as a GitHub Actions secret (SIGNET_MASTER_KEY)
  3. Enable the re-sign workflow (SIGNET_RESIGN_ENABLED=true)
  4. Display the public key for verifier configuration

Requires the GitHub CLI (gh) to be installed and authenticated.`,
	Example: `  # Setup for current repo (auto-detected from git remote)
  signet authority setup-resign

  # Setup for a specific repo
  signet authority setup-resign --repo owner/repo

  # Reuse an existing master key
  signet authority setup-resign --key-file ~/.signet/master.key

  # Dry run (show what would happen without making changes)
  signet authority setup-resign --dry-run`,
	RunE: runSetupResign,
}

func init() {
	f := setupResignCmd.Flags()
	f.StringVar(&setupResignRepo, "repo", "", "GitHub repository (owner/repo). Auto-detected if omitted")
	f.StringVar(&setupResignKeyFile, "key-file", "", "Path to existing master key PEM file. Generated if omitted")
	f.BoolVar(&setupResignDryRun, "dry-run", false, "Show what would be done without making changes")

	authorityCmd.AddCommand(setupResignCmd)
}

func runSetupResign(cmd *cobra.Command, _ []string) error {
	// Check for gh CLI
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("GitHub CLI (gh) is required but not found. Install from https://cli.github.com")
	}

	// Check gh auth status
	if out, err := exec.Command("gh", "auth", "status").CombinedOutput(); err != nil {
		return fmt.Errorf("gh is not authenticated. Run 'gh auth login' first.\n%s", string(out))
	}

	// Resolve repo
	repo, err := resolveRepo()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s Repository: %s\n", styles.Success.Render("✓"), styles.Code.Render(repo))

	// Check that the resign workflow exists in the repo
	if err := checkResignWorkflow(repo); err != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", styles.Warning.Render("⚠"), err.Error())
		fmt.Fprintf(os.Stderr, "  The signet-resign.yml workflow must be committed to the repo first.\n")
		fmt.Fprintf(os.Stderr, "  See: .github/workflows/signet-resign.yml\n")
	}

	// Generate or load key
	keyPEM, pubHex, err := resolveKey()
	if err != nil {
		return err
	}

	if setupResignDryRun {
		fmt.Fprintf(os.Stderr, "\n%s Dry run — no changes made\n", styles.Warning.Render("⚠"))
		fmt.Fprintf(os.Stderr, "  Would set secret  SIGNET_MASTER_KEY on %s\n", repo)
		fmt.Fprintf(os.Stderr, "  Would set variable SIGNET_RESIGN_ENABLED=true on %s\n", repo)
		fmt.Fprintf(os.Stderr, "  Public key: %s\n", pubHex)
		return nil
	}

	// Set GitHub secret
	fmt.Fprintf(os.Stderr, "\n%s Setting SIGNET_MASTER_KEY secret...\n", styles.Subtle.Render("→"))
	if err := ghSetSecret(repo, "SIGNET_MASTER_KEY", string(keyPEM)); err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Secret SIGNET_MASTER_KEY configured\n", styles.Success.Render("✓"))

	// Set GitHub variable
	fmt.Fprintf(os.Stderr, "%s Setting SIGNET_RESIGN_ENABLED variable...\n", styles.Subtle.Render("→"))
	if err := ghSetVariable(repo, "SIGNET_RESIGN_ENABLED", "true"); err != nil {
		return fmt.Errorf("failed to set variable: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Variable SIGNET_RESIGN_ENABLED=true configured\n", styles.Success.Render("✓"))

	// Summary
	fmt.Fprintf(os.Stderr, "\n%s Re-sign workflow configured for %s\n", styles.Success.Render("✓"), styles.Code.Render(repo))
	fmt.Fprintf(os.Stderr, "  Public key: %s\n", pubHex)
	fmt.Fprintf(os.Stderr, "\n  Next merge to main will be re-signed automatically.\n")
	fmt.Fprintf(os.Stderr, "  Verify with: git log --show-signature\n")

	return nil
}

// resolveRepo determines the GitHub repo from --repo flag or git remote.
func resolveRepo() (string, error) {
	if setupResignRepo != "" {
		parts := strings.SplitN(setupResignRepo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("invalid repo format %q, expected owner/repo", setupResignRepo)
		}
		return setupResignRepo, nil
	}

	// Auto-detect from gh
	out, err := exec.Command("gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").Output()
	if err != nil {
		return "", fmt.Errorf("could not detect repository. Use --repo owner/repo or run from a git checkout")
	}
	repo := strings.TrimSpace(string(out))
	if repo == "" {
		return "", fmt.Errorf("could not detect repository. Use --repo owner/repo")
	}
	return repo, nil
}

// checkResignWorkflow verifies that the resign workflow exists in the repo.
func checkResignWorkflow(repo string) error {
	out, err := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/contents/.github/workflows/signet-resign.yml", repo),
		"--jq", ".name",
	).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("signet-resign.yml workflow not found in %s", repo)
	}
	return nil
}

// resolveKey loads an existing key or generates a new one.
// Returns (PEM bytes, hex-encoded public key, error).
func resolveKey() ([]byte, string, error) {
	if setupResignKeyFile != "" {
		return loadExistingKey(setupResignKeyFile)
	}
	return generateKey()
}

func loadExistingKey(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found in %s", path)
	}

	var pubKey ed25519.PublicKey
	switch block.Type {
	case "ED25519 PRIVATE KEY":
		// Signet raw seed format
		if len(block.Bytes) != ed25519.SeedSize {
			return nil, "", fmt.Errorf("invalid seed size in %s", path)
		}
		priv := ed25519.NewKeyFromSeed(block.Bytes)
		pubKey = priv.Public().(ed25519.PublicKey)
	case "PRIVATE KEY":
		// PKCS#8 format
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		edKey, ok := raw.(ed25519.PrivateKey)
		if !ok {
			return nil, "", fmt.Errorf("key is not Ed25519")
		}
		pubKey = edKey.Public().(ed25519.PublicKey)
	default:
		return nil, "", fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	pubHex := hex.EncodeToString(pubKey)
	fmt.Fprintf(os.Stderr, "%s Using existing key from %s\n", styles.Success.Render("✓"), styles.Code.Render(path))
	return data, pubHex, nil
}

func generateKey() ([]byte, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	pubHex := hex.EncodeToString(pub)
	fmt.Fprintf(os.Stderr, "%s Generated new Ed25519 master key\n", styles.Success.Render("✓"))
	return keyPEM, pubHex, nil
}

// ghSetSecret sets a GitHub Actions secret on a repo.
func ghSetSecret(repo, name, value string) error {
	cmd := exec.Command("gh", "secret", "set", name, "--repo", repo)
	cmd.Stdin = strings.NewReader(value)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ghSetVariable sets or updates a GitHub Actions variable on a repo.
func ghSetVariable(repo, name, value string) error {
	// Try set first (creates new variable)
	cmd := exec.Command("gh", "variable", "set", name, "--repo", repo, "--body", value)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
