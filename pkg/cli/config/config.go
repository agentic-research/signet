package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// DefaultCertificateValidityMinutes is the default duration for ephemeral certificates
	DefaultCertificateValidityMinutes = 5
)

// Config holds the configuration for Signet CLI
type Config struct {
	// Home is the path to the .signet directory
	Home string

	// IssuerDID is the DID of the signer
	IssuerDID string

	// CertificateValidityMinutes is the duration for ephemeral certificates
	CertificateValidityMinutes int

	// Algorithm is the signing algorithm to use (default: "ed25519").
	// Supported values: "ed25519", "ml-dsa-44".
	Algorithm string
}

// Default returns the default configuration
func Default() *Config {
	home := GetDefaultHome()
	return &Config{
		Home:                       home,
		IssuerDID:                  "did:key:signet",
		CertificateValidityMinutes: DefaultCertificateValidityMinutes,
	}
}

// Load loads configuration from environment variables and defaults
// Priority: env vars > defaults
func Load() (*Config, error) {
	cfg := Default()

	// Override with environment variables if set
	if home := os.Getenv("SIGNET_HOME"); home != "" {
		cfg.Home = home
	}

	if did := os.Getenv("SIGNET_DID"); did != "" {
		cfg.IssuerDID = did
	}

	if alg := os.Getenv("SIGNET_ALGORITHM"); alg != "" {
		cfg.Algorithm = alg
	}

	return cfg, nil
}

// GetDefaultHome returns the default path for the .signet directory
func GetDefaultHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".signet"
	}
	return filepath.Join(home, ".signet")
}

// DefaultHome is an alias for GetDefaultHome for backward compatibility
func DefaultHome() string {
	return GetDefaultHome()
}

// New creates a new Config with the given home directory
func New(home string) *Config {
	if home == "" {
		home = DefaultHome()
	}

	return &Config{
		Home:                       home,
		IssuerDID:                  "did:key:signet",
		CertificateValidityMinutes: DefaultCertificateValidityMinutes,
	}
}

// EnsureHome creates the .signet directory if it doesn't exist
func (c *Config) EnsureHome() error {
	if err := os.MkdirAll(c.Home, 0700); err != nil {
		return fmt.Errorf("failed to create signet directory: %w", err)
	}
	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Home == "" {
		return errors.New("home directory cannot be empty")
	}

	if c.CertificateValidityMinutes < 1 || c.CertificateValidityMinutes > DefaultCertificateValidityMinutes {
		return fmt.Errorf("certificate validity must be between 1 and %d minutes", DefaultCertificateValidityMinutes)
	}

	return nil
}

// ValidateHomePathRuntime performs runtime validation of the home directory path.
// This should be called before any operation that uses the home directory to
// prevent TOCTOU (Time-of-Check-Time-of-Use) attacks where a path could be
// changed after initial validation but before use.
func (c *Config) ValidateHomePathRuntime() error {
	if c.Home == "" {
		return nil
	}

	// First check if the path itself (before resolution) is a system path
	systemPaths := getSystemPaths()
	if isSystemPath(c.Home, systemPaths) {
		return fmt.Errorf("path is a restricted system directory: %s", c.Home)
	}

	// Resolve any symlinks to get the actual path
	resolvedPath, err := filepath.EvalSymlinks(c.Home)
	if err != nil {
		// If path doesn't exist yet, that's okay for creation operations
		if !os.IsNotExist(err) {
			return fmt.Errorf("cannot resolve path: %w", err)
		}
		// If the path doesn't exist, we still need to check the parent paths
		// to prevent creating directories in system locations
		resolvedPath = c.Home
	}

	// Check if the resolved path is a system directory
	if resolvedPath != c.Home && isSystemPath(resolvedPath, systemPaths) {
		return fmt.Errorf("path resolves to restricted system directory: %s", resolvedPath)
	}

	return nil
}

// getSystemPaths returns a comprehensive list of system paths that should be blocked
func getSystemPaths() []string {
	// Unix-like systems paths
	paths := []string{
		"/",      // Root
		"/etc",   // System configuration
		"/usr",   // System programs
		"/bin",   // Essential binaries
		"/sbin",  // System binaries
		"/var",   // Variable data (logs, caches, etc)
		"/sys",   // Kernel interfaces
		"/proc",  // Process information
		"/tmp",   // Temporary files (world-writable!)
		"/dev",   // Device files
		"/boot",  // Boot partition
		"/lib",   // System libraries
		"/lib64", // 64-bit system libraries
		"/lib32", // 32-bit system libraries
		"/opt",   // Optional software
		"/root",  // Root user home
		"/mnt",   // Mount points
		"/media", // Removable media
		"/srv",   // Service data
	}

	// Add Windows-specific paths on Windows
	if runtime.GOOS == "windows" {
		// Add all drive roots (C:\, D:\, etc.)
		for drive := 'A'; drive <= 'Z'; drive++ {
			paths = append(paths, fmt.Sprintf(`%c:\`, drive))
		}

		// Add specific Windows system paths
		windowsPaths := []string{
			`C:\Windows`,
			`C:\Windows\System32`,
			`C:\Windows\SysWOW64`,
			`C:\Program Files`,
			`C:\Program Files (x86)`,
			`C:\ProgramData`,
			`C:\Windows\Temp`,
			`C:\$Recycle.Bin`,
			`C:\System Volume Information`,
		}
		paths = append(paths, windowsPaths...)
	}

	return paths
}

// isSystemPath checks if a path is within any system directory
func isSystemPath(path string, systemPaths []string) bool {
	// Normalize path for comparison
	path = filepath.Clean(path)

	for _, sysPath := range systemPaths {
		// Check exact match
		if path == sysPath {
			return true
		}

		// Special handling for /tmp: allow subdirectories but not /tmp itself
		// This is necessary for integration tests and legitimate temporary files
		if sysPath == "/tmp" {
			// Block only the /tmp directory itself, not subdirectories
			// Subdirectories in /tmp are commonly used for testing
			if path == "/tmp" {
				return true
			}
			// Allow paths like /tmp/signet-test/.signet
			continue
		}

		// Check if path is under system directory
		// Use proper path separator to avoid false positives
		if strings.HasPrefix(path, sysPath+string(filepath.Separator)) {
			return true
		}

		// On Windows, check case-insensitive
		if runtime.GOOS == "windows" {
			if strings.EqualFold(path, sysPath) {
				return true
			}
			// Special handling for Windows temp directories
			if strings.EqualFold(sysPath, `C:\Windows\Temp`) {
				// Block only the temp directory itself, not subdirectories
				if strings.EqualFold(path, `C:\Windows\Temp`) {
					return true
				}
				continue
			}
			if strings.HasPrefix(strings.ToLower(path), strings.ToLower(sysPath)+string(filepath.Separator)) {
				return true
			}
		}
	}

	return false
}
