package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/spf13/cobra"
)

var (
	registerToken    string
	registerEndpoint string
	registerMCPURL   string
)

var authRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an agent with a GitHub token (no browser needed)",
	Long: `Register a headless agent for MCP access using a GitHub personal access token.
No browser required — designed for CI/CD environments and autonomous agents.

  1. Validates the GitHub token
  2. Requests a signed client certificate via /api/cert/register
  3. Saves cert + key to ~/.signet/mcp/rosary/
  4. Configures Claude Code (if installed)`,
	Example: `  # Register with a GitHub token
  signet auth register --github-token ghp_xxx

  # Register using GITHUB_TOKEN env var
  export GITHUB_TOKEN=ghp_xxx
  signet auth register`,
	RunE: runAuthRegister,
}

func init() {
	f := authRegisterCmd.Flags()
	f.StringVar(&registerToken, "github-token", "", "GitHub personal access token (or set GITHUB_TOKEN env var)")
	f.StringVar(&registerEndpoint, "endpoint", "https://rosary.bot", "Dashboard URL")
	f.StringVar(&registerMCPURL, "mcp-url", "https://mcp.rosary.bot/mcp", "MCP endpoint URL")

	authCmd.AddCommand(authRegisterCmd)
}

func runAuthRegister(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	fmt.Fprintln(os.Stderr)

	// Resolve token
	token := registerToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub token required: use --github-token or set GITHUB_TOKEN env var")
	}

	// Check existing cert
	certDir := filepath.Join(cfg.Home, "mcp", "rosary")
	if renewed, err := tryRenewExisting(certDir); err == nil && renewed {
		return nil
	}

	// Generate keypair
	pubPEM, privPEM, err := generateClientKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	defer keys.ZeroizeBytes(privPEM)
	fmt.Fprintf(os.Stderr, "%s Generated ECDSA P-256 keypair\n", styles.Success.Render("✓"))

	// Request cert via /api/cert/register (GitHub token auth, no OAuth needed)
	certResp, err := requestCertificateWithGitHub(registerEndpoint, token, pubPEM)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Certificate issued", styles.Success.Render("✓"))
	if certResp.ExpiresAt != "" {
		fmt.Fprintf(os.Stderr, " (expires: %s)", certResp.ExpiresAt)
	}
	fmt.Fprintln(os.Stderr)

	// Save cert bundle (no refresh token for GitHub-based auth)
	authEndpoint = registerEndpoint
	authMCPURL = registerMCPURL
	certDir, err = saveCertBundle(cfg.Home, certResp, privPEM, "")
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	fmt.Fprintf(os.Stderr, "%s Saved to %s\n", styles.Success.Render("✓"), styles.Code.Render(certDir))

	// Configure Claude Code
	if err := configureClaude(registerMCPURL, certPath, keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s Could not auto-configure Claude Code: %v\n", styles.Warning.Render("⚠"), err)
		printManualConfig(registerMCPURL, certPath, keyPath)
	} else {
		fmt.Fprintf(os.Stderr, "%s Claude Code configured\n", styles.Success.Render("✓"))
	}

	fmt.Fprintf(os.Stderr, "\n  Ready!\n\n")
	return nil
}

// requestCertificateWithGitHub calls /api/cert/register with a GitHub PAT.
func requestCertificateWithGitHub(endpoint, ghToken string, pubKeyPEM []byte) (*certResponse, error) {
	return requestCertificate(endpoint+"/api/cert/register", ghToken, pubKeyPEM)
}
