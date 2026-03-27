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
	registerAgent    string
	registerScope    string
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
	Example: `  # Register a human identity
  signet auth register --github-token ghp_xxx

  # Register an agent with scoped identity
  signet auth register --agent dev-agent --scope repo:signet

  # Register using GITHUB_TOKEN env var
  export GITHUB_TOKEN=ghp_xxx
  signet auth register --agent staging-agent`,
	RunE: runAuthRegister,
}

func init() {
	f := authRegisterCmd.Flags()
	f.StringVar(&registerToken, "github-token", "", "GitHub personal access token (or set GITHUB_TOKEN env var)")
	f.StringVar(&registerEndpoint, "endpoint", "", "Dashboard URL (defaults to config)")
	f.StringVar(&registerMCPURL, "mcp-url", "", "MCP endpoint URL (defaults to config)")
	f.StringVar(&registerAgent, "agent", "", "Agent name (e.g. dev-agent). When set, cert identifies an agent, not a human.")
	f.StringVar(&registerScope, "scope", "", "Scope restriction (e.g. repo:signet). Limits what the agent is authorized to do.")

	authCmd.AddCommand(authRegisterCmd)
}

func runAuthRegister(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	fmt.Fprintln(os.Stderr)

	// Step 0: Ensure Endpoint and MCP URL are defined (Prompt if not)
	if registerEndpoint == "" {
		registerEndpoint = cfg.AuthEndpoint
	}
	if registerMCPURL == "" {
		registerMCPURL = cfg.MCPURL
	}

	needsSave := false
	if registerEndpoint == "" {
		fmt.Printf("%s Enter Signet Dashboard URL: ", styles.Info.Render("?"))
		fmt.Scanln(&registerEndpoint)
		if registerEndpoint == "" {
			return fmt.Errorf("dashboard URL is required")
		}
		cfg.AuthEndpoint = registerEndpoint
		needsSave = true
	}

	if registerMCPURL == "" {
		fmt.Printf("%s Enter MCP Endpoint URL: ", styles.Info.Render("?"))
		fmt.Scanln(&registerMCPURL)
		if registerMCPURL == "" {
			return fmt.Errorf("MCP URL is required")
		}
		cfg.MCPURL = registerMCPURL
		needsSave = true
	}

	if needsSave {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Warning: failed to save config: %v\n", styles.Warning.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "%s Configuration saved to %s\n", styles.Success.Render("✓"), filepath.Join(cfg.Home, "config.json"))
		}
	}

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
	certResp, err := requestCertificateWithGitHub(registerEndpoint, token, pubPEM, registerAgent, registerScope)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}

	if registerAgent != "" {
		fmt.Fprintf(os.Stderr, "%s Agent certificate issued for %s",
			styles.Success.Render("✓"), styles.Code.Render(registerAgent))
	} else {
		fmt.Fprintf(os.Stderr, "%s Certificate issued", styles.Success.Render("✓"))
	}
	if certResp.expiresAtString() != "" {
		fmt.Fprintf(os.Stderr, " (expires: %s)", certResp.expiresAtString())
	}
	fmt.Fprintln(os.Stderr)

	// Save cert bundle (no refresh token for GitHub-based auth)
	certDir, err = saveCertBundle(cfg.Home, registerEndpoint, registerMCPURL, certResp, privPEM, "")
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
// When agentName is non-empty, the server issues an agent-scoped certificate.
func requestCertificateWithGitHub(endpoint, ghToken string, pubKeyPEM []byte, agentName, scope string) (*certResponse, error) {
	if agentName == "" && scope != "" {
		return nil, fmt.Errorf("--scope can only be used when --agent is set")
	}

	body := map[string]string{
		"public_key": string(pubKeyPEM),
	}
	if agentName != "" {
		body["agent_name"] = agentName
	}
	if agentName != "" && scope != "" {
		body["scope"] = scope
	}
	return requestCertificateWithBody(endpoint+"/api/cert/register", ghToken, body)
}
