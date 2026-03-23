package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultSocketDir returns the path to the user-private directory for agent sockets.
// The directory is created with 0700 permissions if it doesn't exist.
// On Linux, it uses $XDG_RUNTIME_DIR/signet (typically /run/user/<uid>/signet).
// On other platforms (macOS, etc.), it uses $HOME/.signet/run.
func DefaultSocketDir() (string, error) {
	var baseDir string

	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			baseDir = filepath.Join(xdg, "signet")
		}
	}

	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		baseDir = filepath.Join(home, ".signet", "run")
	}

	// Create the directory with user-only permissions (0700).
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create socket directory %s: %w", baseDir, err)
	}

	// Verify the directory is not a symlink and has restrictive permissions.
	info, err := os.Lstat(baseDir)
	if err != nil {
		return "", fmt.Errorf("cannot stat socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("socket directory %s is a symlink (possible attack)", baseDir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("socket directory %s has insecure permissions %o (expected 0700)", baseDir, perm)
	}

	return baseDir, nil
}

// DefaultSocketPath generates a secure default socket path with a random suffix.
// The socket is placed in a user-private directory (0700) with a cryptographically
// random 8-byte hex suffix to prevent path prediction attacks.
func DefaultSocketPath() (string, error) {
	dir, err := DefaultSocketDir()
	if err != nil {
		return "", err
	}

	suffix, err := randomHex(8)
	if err != nil {
		return "", fmt.Errorf("cannot generate random socket suffix: %w", err)
	}

	return filepath.Join(dir, fmt.Sprintf("agent-%s.sock", suffix)), nil
}

// randomHex returns n bytes of cryptographic randomness encoded as hex.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
