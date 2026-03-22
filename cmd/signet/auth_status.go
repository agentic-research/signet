package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/spf13/cobra"
)

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current MCP certificate status",
	RunE:  runAuthStatus,
}

func init() {
	authCmd.AddCommand(authStatusCmd)
}

func runAuthStatus(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	mcpDir := filepath.Join(cfg.Home, "mcp")

	entries, err := os.ReadDir(mcpDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "%s No MCP certificates configured. Run: signet auth login\n", styles.Info.Render("→"))
			return nil
		}
		return err
	}

	found := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(mcpDir, entry.Name(), "metadata.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var meta certMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		found = true
		fmt.Fprintf(os.Stderr, "\n%s %s\n", styles.Success.Render("●"), styles.Code.Render(entry.Name()))
		fmt.Fprintf(os.Stderr, "  Endpoint: %s\n", meta.Endpoint)
		fmt.Fprintf(os.Stderr, "  MCP URL:  %s\n", meta.MCPURL)
		fmt.Fprintf(os.Stderr, "  Issued:   %s\n", meta.IssuedAt)

		if meta.ExpiresAt != "" {
			expiry, err := time.Parse(time.RFC3339, meta.ExpiresAt)
			if err == nil {
				remaining := time.Until(expiry)
				if remaining <= 0 {
					fmt.Fprintf(os.Stderr, "  Expires:  %s %s\n", meta.ExpiresAt, styles.Error.Render("EXPIRED"))
				} else if remaining < 30*24*time.Hour {
					fmt.Fprintf(os.Stderr, "  Expires:  %s %s\n", meta.ExpiresAt, styles.Warning.Render("(expires soon)"))
				} else {
					fmt.Fprintf(os.Stderr, "  Expires:  %s\n", meta.ExpiresAt)
				}
			} else {
				fmt.Fprintf(os.Stderr, "  Expires:  %s\n", meta.ExpiresAt)
			}
		}

		certPath := filepath.Join(mcpDir, entry.Name(), "cert.pem")
		keyPath := filepath.Join(mcpDir, entry.Name(), "key.pem")
		certExists := fileExists(certPath)
		keyExists := fileExists(keyPath)

		if certExists && keyExists {
			fmt.Fprintf(os.Stderr, "  Files:    %s\n", styles.Success.Render("cert.pem + key.pem"))
		} else {
			fmt.Fprintf(os.Stderr, "  Files:    %s\n", styles.Error.Render("missing"))
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "%s No MCP certificates configured. Run: signet auth login\n", styles.Info.Render("→"))
	}

	fmt.Fprintln(os.Stderr)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
