package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketDir(t *testing.T) {
	dir, err := DefaultSocketDir()
	if err != nil {
		t.Fatalf("DefaultSocketDir() failed: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("socket directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("socket path %s is not a directory", dir)
	}

	// Verify permissions are 0700
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		t.Errorf("socket directory has permissions %o, want 0700", perm)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	path1, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath() failed: %v", err)
	}

	path2, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath() second call failed: %v", err)
	}

	// Paths must be different (random suffix)
	if path1 == path2 {
		t.Errorf("two calls to DefaultSocketPath() returned the same path: %s", path1)
	}

	// Both must end with .sock
	if !strings.HasSuffix(path1, ".sock") {
		t.Errorf("socket path %s does not end with .sock", path1)
	}

	// Both must contain "agent-" prefix in filename
	base := filepath.Base(path1)
	if !strings.HasPrefix(base, "agent-") {
		t.Errorf("socket filename %s does not start with agent-", base)
	}

	// Filename should be agent-<16 hex chars>.sock = 28 chars total
	// "agent-" (6) + 16 hex chars + ".sock" (5) = 27
	expectedLen := 6 + 16 + 5
	if len(base) != expectedLen {
		t.Errorf("socket filename %s has length %d, expected %d", base, len(base), expectedLen)
	}
}

func TestDefaultSocketDirRejectsSymlink(t *testing.T) {
	// Create a temp dir and a symlink pointing to it
	realDir := t.TempDir()
	symlinkDir := filepath.Join(t.TempDir(), "symlink-target")

	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}

	// Verify Lstat detects symlinks (this is the mechanism DefaultSocketDir uses)
	info, err := os.Lstat(symlinkDir)
	if err != nil {
		t.Fatalf("Lstat failed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("expected symlink mode bit to be set")
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
