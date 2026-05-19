package keystore

import (
	"os"
	"path/filepath"
)

// XDGKeystoreDir returns the signet keystore directory derived from
// XDG_CONFIG_HOME if that environment variable is set.
//
// Behavior:
//   - XDG_CONFIG_HOME set → returns ("$XDG_CONFIG_HOME/signet", true).
//     Callers MUST use this path for both reads and writes; the OS keyring
//     is skipped entirely. This is the canonical test/CI/ephemeral path —
//     `XDG_CONFIG_HOME=$(mktemp -d) signet-git init` puts the master key in
//     an isolated tmpdir without touching the user's real keyring.
//   - XDG_CONFIG_HOME unset → returns ("", false). Callers should use the
//     existing OS keyring path (bit-for-bit backward compatible).
//
// We intentionally do NOT fall back to the XDG-spec default of
// $HOME/.config/signet when XDG_CONFIG_HOME is unset. That would be a
// silent behavior change for any developer who has ~/.config but has
// always used the keyring — they'd suddenly start reading from a
// nonexistent file and fail. Requiring explicit XDG_CONFIG_HOME is the
// opt-in signal.
//
// See signet-b30dd4 for the design discussion.
func XDGKeystoreDir() (dir string, set bool) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		return "", false
	}
	return filepath.Join(xdg, "signet"), true
}
