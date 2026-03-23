package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestValidateHomeDir tests path validation security
func TestValidateHomeDir(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		shouldBlock bool
		description string
	}{
		// Existing system paths (should already be blocked)
		{
			name:        "root_directory",
			path:        "/",
			shouldBlock: true,
			description: "Root directory should be blocked",
		},
		{
			name:        "etc_directory",
			path:        "/etc",
			shouldBlock: true,
			description: "System configuration directory should be blocked",
		},
		{
			name:        "etc_subdirectory",
			path:        "/etc/passwd",
			shouldBlock: true,
			description: "Files under /etc should be blocked",
		},

		// Missing from current implementation - should be blocked but aren't
		{
			name:        "tmp_directory",
			path:        "/tmp",
			shouldBlock: true,
			description: "Temp directory is world-writable and should be blocked",
		},
		{
			name:        "tmp_subdirectory",
			path:        "/tmp/signet",
			shouldBlock: false,
			description: "Subdirectories of /tmp should be allowed for testing and temporary operations",
		},
		{
			name:        "dev_directory",
			path:        "/dev",
			shouldBlock: true,
			description: "Device files directory should be blocked",
		},
		{
			name:        "dev_null",
			path:        "/dev/null",
			shouldBlock: true,
			description: "Device files should be blocked",
		},
		{
			name:        "boot_directory",
			path:        "/boot",
			shouldBlock: true,
			description: "Boot partition should be blocked",
		},
		{
			name:        "lib_directory",
			path:        "/lib",
			shouldBlock: true,
			description: "System libraries should be blocked",
		},
		{
			name:        "lib64_directory",
			path:        "/lib64",
			shouldBlock: true,
			description: "64-bit system libraries should be blocked",
		},

		// Valid paths that should be allowed
		{
			name:        "home_directory",
			path:        filepath.Join(os.Getenv("HOME"), ".signet-test"),
			shouldBlock: false,
			description: "User directories should be allowed",
		},
		{
			name:        "relative_home",
			path:        "~/.signet",
			shouldBlock: false,
			description: "Tilde expansion should work for home dirs",
		},
	}

	// Add Windows-specific tests if on Windows
	if runtime.GOOS == "windows" {
		windowsTests := []struct {
			name        string
			path        string
			shouldBlock bool
			description string
		}{
			{
				name:        "windows_system",
				path:        `C:\Windows`,
				shouldBlock: true,
				description: "Windows system directory should be blocked",
			},
			{
				name:        "windows_system32",
				path:        `C:\Windows\System32`,
				shouldBlock: true,
				description: "Windows System32 should be blocked",
			},
			{
				name:        "program_files",
				path:        `C:\Program Files`,
				shouldBlock: true,
				description: "Program Files should be blocked",
			},
			{
				name:        "program_files_x86",
				path:        `C:\Program Files (x86)`,
				shouldBlock: true,
				description: "Program Files x86 should be blocked",
			},
			{
				name:        "windows_temp",
				path:        `C:\Windows\Temp`,
				shouldBlock: true,
				description: "Windows temp should be blocked",
			},
			{
				name:        "user_dir_windows",
				path:        `C:\Users\test\.signet`,
				shouldBlock: false,
				description: "User directories on Windows should be allowed",
			},
		}
		tests = append(tests, windowsTests...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := New(tt.path)
			err := cfg.ValidateHomePathRuntime()
			blocked := (err != nil)

			if blocked != tt.shouldBlock {
				if tt.shouldBlock {
					t.Errorf("SECURITY VULNERABILITY: %s\nPath '%s' should be blocked but was allowed",
						tt.description, tt.path)
				} else {
					t.Errorf("False positive: %s\nPath '%s' should be allowed but was blocked: %v",
						tt.description, tt.path, err)
				}
			}
		})
	}
}

// TestSymlinkAttacks tests protection against symlink-based attacks
func TestSymlinkAttacks(t *testing.T) {
	// Skip on CI or if we can't create temp dirs
	if os.Getenv("CI") != "" {
		t.Skip("Skipping symlink tests in CI environment")
	}

	tempDir := t.TempDir()

	t.Run("single_symlink_to_etc", func(t *testing.T) {
		// Create a symlink pointing to /etc
		linkPath := filepath.Join(tempDir, "evil-link")
		if err := os.Symlink("/etc", linkPath); err != nil {
			t.Skip("Cannot create symlinks, skipping test")
		}
		defer func() { _ = os.Remove(linkPath) }()

		cfg := New(linkPath)
		err := cfg.ValidateHomePathRuntime()
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Symlink to /etc was not detected")
		}
	})

	t.Run("nested_symlink_attack", func(t *testing.T) {
		// Create nested symlinks: link1 -> link2 -> /etc
		link1 := filepath.Join(tempDir, "link1")
		link2 := filepath.Join(tempDir, "link2")

		if err := os.Symlink("/etc", link2); err != nil {
			t.Skip("Cannot create symlinks, skipping test")
		}
		defer func() { _ = os.Remove(link2) }()

		if err := os.Symlink(link2, link1); err != nil {
			t.Skip("Cannot create nested symlinks, skipping test")
		}
		defer func() { _ = os.Remove(link1) }()

		cfg := New(link1)
		err := cfg.ValidateHomePathRuntime()
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Nested symlink chain to /etc was not detected")
		}
	})

	t.Run("symlink_to_tmp", func(t *testing.T) {
		// Create a symlink pointing to /tmp (should be blocked)
		linkPath := filepath.Join(tempDir, "tmp-link")
		if err := os.Symlink("/tmp", linkPath); err != nil {
			t.Skip("Cannot create symlinks, skipping test")
		}
		defer func() { _ = os.Remove(linkPath) }()

		cfg := New(linkPath)
		err := cfg.ValidateHomePathRuntime()
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Symlink to /tmp was not detected")
		}
	})
}

// TestTOCTOUAttack tests Time-of-Check-Time-of-Use vulnerability
func TestTOCTOUAttack(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping TOCTOU test in CI environment")
	}

	// Use home directory for testing instead of temp
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		t.Skip("HOME not set, skipping test")
	}

	testDir := filepath.Join(homeDir, ".signet-test-toctou")
	defer func() { _ = os.RemoveAll(testDir) }()

	safePath := filepath.Join(testDir, "safe-dir")

	// Create a safe directory first
	if err := os.MkdirAll(safePath, 0o755); err != nil {
		t.Fatal(err)
	}

	// Validate the path (should pass)
	cfg := New(safePath)
	if err := cfg.ValidateHomePathRuntime(); err != nil {
		t.Fatalf("Safe path validation failed: %v", err)
	}

	// Simulate TOCTOU: After validation, replace with symlink to /etc
	if err := os.RemoveAll(safePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", safePath); err != nil {
		t.Skip("Cannot create symlinks, skipping TOCTOU test")
	}
	defer func() { _ = os.Remove(safePath) }()

	// Now when the application uses the path, it's actually pointing to /etc
	// This demonstrates the TOCTOU vulnerability:
	// 1. Path was validated as safe
	// 2. Path was replaced with symlink to /etc
	// 3. Application would now be using /etc instead of safe directory

	resolvedPath, err := filepath.EvalSymlinks(safePath)
	if err == nil && resolvedPath == "/etc" {
		t.Log("TOCTOU attack scenario created - path now points to /etc")

		// Test the runtime validation - it should catch this!
		err := cfg.ValidateHomePathRuntime()
		if err == nil {
			t.Error("SECURITY VULNERABILITY: Runtime validation failed to detect TOCTOU attack")
		} else {
			t.Log("SUCCESS: Runtime validation caught TOCTOU attack:", err)
		}
	}
}
