package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
remaining validity drops below the renew-before threshold.

Features:
  - PID file prevents double-run
  - Exponential backoff on consecutive renewal failures (1m → 2m → 4m → ... → 30m)
  - Detects dead refresh token and exits with actionable error
  - Watches all cert directories under ~/.signet/mcp/*/
  - Graceful shutdown on SIGTERM/SIGINT`,
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
  # WantedBy=multi-user.target

  # Run as macOS launchd agent
  # Save to ~/Library/LaunchAgents/bot.rosary.signet-daemon.plist
  # <plist version="1.0"><dict>
  # <key>Label</key><string>bot.rosary.signet-daemon</string>
  # <key>ProgramArguments</key><array>
  #   <string>/usr/local/bin/signet</string>
  #   <string>auth</string><string>daemon</string>
  # </array>
  # <key>RunAtLoad</key><true/>
  # <key>KeepAlive</key><true/>
  # </dict></plist>`,
	RunE: runAuthDaemon,
}

func init() {
	f := authDaemonCmd.Flags()
	f.DurationVar(&daemonCheckInterval, "check-interval", 30*time.Minute, "How often to check cert expiry")
	f.DurationVar(&daemonRenewBefore, "renew-before", 1*time.Hour, "Renew when remaining validity is below this")

	authCmd.AddCommand(authDaemonCmd)
}

const (
	pidFileName         = "daemon.pid"
	maxBackoff          = 30 * time.Minute
	initialBackoff      = 1 * time.Minute
	maxConsecutiveFails = 10 // after this many, exit with error
)

func runAuthDaemon(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()

	// Validate intervals
	if daemonCheckInterval <= 0 {
		return fmt.Errorf("--check-interval must be positive (got %s)", daemonCheckInterval)
	}
	if daemonRenewBefore <= 0 {
		return fmt.Errorf("--renew-before must be positive (got %s)", daemonRenewBefore)
	}

	// PID file — prevent double-run
	pidPath := filepath.Join(cfg.Home, pidFileName)
	if err := acquirePIDFile(pidPath); err != nil {
		return err
	}
	defer removePIDFile(pidPath)

	// Discover cert directories
	certDirs, err := discoverCertDirs(cfg.Home)
	if err != nil || len(certDirs) == 0 {
		return fmt.Errorf("no certificates found under %s/mcp/ — run 'signet auth login' first", cfg.Home)
	}

	fmt.Fprintf(os.Stderr, "%s signet auth daemon starting\n", styles.Info.Render("→"))
	fmt.Fprintf(os.Stderr, "  PID:            %d\n", os.Getpid())
	fmt.Fprintf(os.Stderr, "  Check interval: %s\n", daemonCheckInterval)
	fmt.Fprintf(os.Stderr, "  Renew before:   %s\n", daemonRenewBefore)
	fmt.Fprintf(os.Stderr, "  Watching:       %d cert(s)\n", len(certDirs))
	for _, dir := range certDirs {
		meta, _ := loadMetadata(dir)
		if meta != nil {
			fmt.Fprintf(os.Stderr, "    %s (expires: %s)\n", styles.Code.Render(filepath.Base(dir)), meta.ExpiresAt)
		}
	}
	fmt.Fprintln(os.Stderr)

	// Graceful shutdown on signal (matches mache serve pattern)
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(daemonCheckInterval)
	defer ticker.Stop()

	consecutiveFails := 0

	// Check immediately on startup
	if failures := checkAllCerts(certDirs, daemonRenewBefore); failures > 0 {
		consecutiveFails = failures
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\n%s Daemon shutting down (PID %d)\n", styles.Info.Render("→"), os.Getpid())
			return nil
		case <-ticker.C:
			failures := checkAllCerts(certDirs, daemonRenewBefore)
			if failures > 0 {
				consecutiveFails += failures

				if consecutiveFails >= maxConsecutiveFails {
					return fmt.Errorf("too many consecutive renewal failures (%d) — refresh token may be expired. Run 'signet auth login' to re-authenticate", consecutiveFails)
				}

				// Exponential backoff: slow down the ticker
				backoff := initialBackoff * time.Duration(1<<min(consecutiveFails, 5))
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				ticker.Reset(backoff)
				fmt.Fprintf(os.Stderr, "%s Next check in %s (backoff, %d consecutive failures)\n",
					styles.Warning.Render("⚠"), backoff.Round(time.Second), consecutiveFails)
			} else {
				// Reset on success
				if consecutiveFails > 0 {
					consecutiveFails = 0
					ticker.Reset(daemonCheckInterval)
					fmt.Fprintf(os.Stderr, "%s Backoff reset, resuming normal interval\n", styles.Success.Render("✓"))
				}
			}
		}
	}
}

// checkAllCerts checks all cert directories and renews as needed.
// Returns the number of certs that failed to renew.
func checkAllCerts(certDirs []string, renewBefore time.Duration) int {
	failures := 0
	for _, dir := range certDirs {
		name := filepath.Base(dir)
		result := checkAndRenew(dir, renewBefore, name)
		switch result {
		case renewResultOK:
			// fine
		case renewResultRenewed:
			fmt.Fprintf(os.Stderr, "%s [%s] Certificate renewed at %s\n",
				styles.Success.Render("✓"), name, time.Now().Format(time.RFC3339))
		case renewResultFailed:
			failures++
		case renewResultNoRefreshToken:
			fmt.Fprintf(os.Stderr, "%s [%s] No refresh token — run 'signet auth login' to fix\n",
				styles.Error.Render("✗"), name)
			failures++
		}
	}
	return failures
}

type renewResult int

const (
	renewResultOK             renewResult = iota
	renewResultRenewed        renewResult = iota
	renewResultFailed         renewResult = iota
	renewResultNoRefreshToken renewResult = iota
)

// checkAndRenew checks if a cert needs renewal and renews if needed.
func checkAndRenew(certDir string, renewBefore time.Duration, name string) renewResult {
	meta, err := loadMetadata(certDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s [%s] Failed to read metadata: %v\n", styles.Warning.Render("⚠"), name, err)
		return renewResultFailed
	}

	if meta.ExpiresAt == "" {
		return renewResultOK
	}

	expiry, err := time.Parse(time.RFC3339, meta.ExpiresAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s [%s] Failed to parse expiry: %v\n", styles.Warning.Render("⚠"), name, err)
		return renewResultFailed
	}

	remaining := time.Until(expiry)
	if remaining > renewBefore {
		fmt.Fprintf(os.Stderr, "%s [%s] OK (remaining: %s)\n",
			styles.Subtle.Render("·"), name, remaining.Round(time.Minute))
		return renewResultOK
	}

	// Check for dead refresh token before attempting renewal
	if meta.RefreshToken == "" {
		return renewResultNoRefreshToken
	}

	// Time to renew
	fmt.Fprintf(os.Stderr, "%s [%s] Expiring soon (%s remaining), renewing...\n",
		styles.Warning.Render("⚠"), name, remaining.Round(time.Minute))

	renewed, err := tryRenewExisting(certDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s [%s] Renewal error: %v\n", styles.Error.Render("✗"), name, err)
		return renewResultFailed
	}
	if !renewed {
		fmt.Fprintf(os.Stderr, "%s [%s] Renewal returned false (may need re-login)\n", styles.Warning.Render("⚠"), name)
		return renewResultFailed
	}

	return renewResultRenewed
}

// discoverCertDirs finds all cert directories under ~/.signet/mcp/*/
func discoverCertDirs(signetHome string) ([]string, error) {
	mcpDir := filepath.Join(signetHome, "mcp")
	entries, err := os.ReadDir(mcpDir)
	if err != nil {
		return nil, err
	}

	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(mcpDir, entry.Name())
		// Must have metadata.json to be a valid cert dir
		if _, err := os.Stat(filepath.Join(dir, "metadata.json")); err == nil {
			dirs = append(dirs, dir)
		}
	}
	return dirs, nil
}

// acquirePIDFile writes the current PID and checks for stale PIDs.
func acquirePIDFile(path string) error {
	// Check for existing PID file
	data, err := os.ReadFile(path)
	if err == nil {
		pid, err := strconv.Atoi(string(data))
		if err == nil {
			// Check if the process is still running
			proc, err := os.FindProcess(pid)
			if err == nil {
				// On Unix, FindProcess always succeeds. Send signal 0 to check.
				if err := proc.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("daemon already running (PID %d, file %s)", pid, path)
				}
			}
		}
		// Stale PID file — remove it
		_ = os.Remove(path)
	}

	// Write our PID
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), fs.FileMode(0o644))
}

// removePIDFile removes the PID file on shutdown.
func removePIDFile(path string) {
	_ = os.Remove(path)
}
