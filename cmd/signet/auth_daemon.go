package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/spf13/cobra"
)

var (
	daemonCheckInterval time.Duration
	daemonRenewBefore   time.Duration
)

var authDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Auto-renew certificates before expiry",
	Long: `Run a background process that monitors certificate expiry and
auto-renews before the certificate expires. Useful for long-running
agents, CI/CD environments, and MCP clients.

The daemon checks certificate expiry periodically and renews when the
remaining validity drops below the renew-before threshold.`,
	Example: `  # Default: check every 30m, renew 1h before expiry
  signet auth daemon

  # Custom intervals
  signet auth daemon --check-interval 15m --renew-before 2h

  # Run as systemd service
  # [Unit]
  # Description=Signet cert renewal daemon
  # After=network.target
  # [Service]
  # ExecStart=/usr/local/bin/signet auth daemon
  # Restart=always
  # [Install]
  # WantedBy=multi-user.target`,
	RunE: runAuthDaemon,
}

func init() {
	f := authDaemonCmd.Flags()
	f.DurationVar(&daemonCheckInterval, "check-interval", 30*time.Minute, "How often to check cert expiry")
	f.DurationVar(&daemonRenewBefore, "renew-before", 1*time.Hour, "Renew when remaining validity is below this")

	authCmd.AddCommand(authDaemonCmd)
}

func runAuthDaemon(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	certDir := filepath.Join(cfg.Home, "mcp", "rosary")

	fmt.Fprintf(os.Stderr, "%s signet auth daemon starting\n", styles.Info.Render("→"))
	fmt.Fprintf(os.Stderr, "  Check interval: %s\n", daemonCheckInterval)
	fmt.Fprintf(os.Stderr, "  Renew before:   %s\n", daemonRenewBefore)
	fmt.Fprintf(os.Stderr, "  Cert dir:       %s\n", styles.Code.Render(certDir))
	fmt.Fprintln(os.Stderr)

	// Check that a cert exists before starting the loop
	meta, err := loadMetadata(certDir)
	if err != nil {
		return fmt.Errorf("no existing certificate found at %s — run 'signet auth login' first", certDir)
	}

	fmt.Fprintf(os.Stderr, "%s Monitoring cert (expires: %s)\n", styles.Success.Render("✓"), meta.ExpiresAt)

	// Graceful shutdown on signal (matches mache serve pattern)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(daemonCheckInterval)
	defer ticker.Stop()

	// Check immediately on startup
	if renewed := checkAndRenew(certDir, daemonRenewBefore); renewed {
		fmt.Fprintf(os.Stderr, "%s Certificate renewed on startup\n", styles.Success.Render("✓"))
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\n%s Daemon shutting down\n", styles.Info.Render("→"))
			return nil
		case <-ticker.C:
			if renewed := checkAndRenew(certDir, daemonRenewBefore); renewed {
				fmt.Fprintf(os.Stderr, "%s Certificate renewed at %s\n",
					styles.Success.Render("✓"),
					time.Now().Format(time.RFC3339))
			}
		}
	}
}

// checkAndRenew checks if the cert needs renewal and renews if needed.
// Returns true if the cert was renewed.
func checkAndRenew(certDir string, renewBefore time.Duration) bool {
	meta, err := loadMetadata(certDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to read metadata: %v\n", styles.Warning.Render("⚠"), err)
		return false
	}

	if meta.ExpiresAt == "" {
		return false
	}

	expiry, err := time.Parse(time.RFC3339, meta.ExpiresAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to parse expiry: %v\n", styles.Warning.Render("⚠"), err)
		return false
	}

	remaining := time.Until(expiry)
	if remaining > renewBefore {
		// Not yet time to renew
		fmt.Fprintf(os.Stderr, "%s Cert OK (remaining: %s)\n",
			styles.Subtle.Render("·"),
			remaining.Round(time.Minute))
		return false
	}

	// Time to renew
	fmt.Fprintf(os.Stderr, "%s Cert expiring soon (%s remaining), renewing...\n",
		styles.Warning.Render("⚠"),
		remaining.Round(time.Minute))

	renewed, err := tryRenewExisting(certDir)
	if err != nil || !renewed {
		fmt.Fprintf(os.Stderr, "%s Renewal failed (will retry): %v\n", styles.Error.Render("✗"), err)
		return false
	}

	return true
}
