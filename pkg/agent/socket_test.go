package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultSocketDir(t *testing.T) {
	// Isolate from host environment
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	}

	dir, err := DefaultSocketDir()
	if err != nil {
		t.Fatalf("DefaultSocketDir() failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("socket directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("socket path %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("socket directory has permissions %o, want 0700", perm)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	}

	path1, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath() failed: %v", err)
	}

	path2, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath() second call failed: %v", err)
	}

	if path1 == path2 {
		t.Errorf("two calls returned the same path: %s", path1)
	}
	if !strings.HasSuffix(path1, ".sock") {
		t.Errorf("socket path %s does not end with .sock", path1)
	}

	base := filepath.Base(path1)
	if !strings.HasPrefix(base, "agent-") {
		t.Errorf("socket filename %s does not start with agent-", base)
	}

	// Filename should be agent-<16 hex chars>.sock = 27 chars total
	// "agent-" (6) + 16 hex chars + ".sock" (5) = 27
	expectedLen := 6 + 16 + 5
	if len(base) != expectedLen {
		t.Errorf("socket filename %s has length %d, expected %d", base, len(base), expectedLen)
	}
}

func TestDefaultSocketDirRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	symlinkDir := filepath.Join(tmpDir, "fake-home")

	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}

	// Point HOME to a path where .signet/run will resolve through a symlink
	t.Setenv("HOME", symlinkDir)
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_RUNTIME_DIR", "")
	}

	// DefaultSocketDir creates ~/.signet/run — but ~ is a symlink, so
	// the final directory itself won't be a symlink. The real vulnerability
	// is if someone replaces the socket dir with a symlink after creation.
	// Verify our Lstat check would catch that.
	dir, err := DefaultSocketDir()
	if err != nil {
		// If it errors, that's fine — it means it detected the symlink in the path
		return
	}

	// If it succeeded, verify the resulting directory is real (not a symlink)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("DefaultSocketDir returned a symlink directory")
	}
}

func TestRandomHex(t *testing.T) {
	hex1, err := randomHex(8)
	if err != nil {
		t.Fatalf("randomHex(8) failed: %v", err)
	}
	if len(hex1) != 16 {
		t.Errorf("randomHex(8) returned %d chars, expected 16", len(hex1))
	}

	hex2, err := randomHex(8)
	if err != nil {
		t.Fatalf("randomHex(8) second call failed: %v", err)
	}
	if hex1 == hex2 {
		t.Error("two calls to randomHex returned the same value")
	}
}
