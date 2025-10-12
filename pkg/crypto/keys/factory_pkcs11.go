//go:build pkcs11

package keys

import (
	"crypto"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/jamestexas/go-platform-signers/pkcs11"
)

// validateModulePath checks for path traversal attacks and ensures the path is absolute.
func validateModulePath(path string) error {
	// Reject paths containing ".." to prevent path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("module path cannot contain '..' (path traversal risk)")
	}

	// Clean the path to resolve any ./ or redundant separators
	cleaned := filepath.Clean(path)

	// Ensure it's an absolute path
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("module path must be absolute, got: %s", path)
	}

	return nil
}

// validateKeyLabel checks for control characters and ensures reasonable length.
func validateKeyLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("key label cannot be empty")
	}

	if len(label) > 256 {
		return fmt.Errorf("key label too long (max 256 characters)")
	}

	// Check for control characters
	for _, r := range label {
		if unicode.IsControl(r) {
			return fmt.Errorf("key label contains invalid control character")
		}
	}

	return nil
}

// validateSlotID ensures the slot ID is within the valid PKCS#11 range.
func validateSlotID(slotID uint) error {
	// PKCS#11 slot IDs are typically 16-bit values
	if slotID > 65535 {
		return fmt.Errorf("slot-id must be between 0 and 65535, got: %d", slotID)
	}
	return nil
}

// NewSigner is the factory function for creating signers.
// This is the enhanced implementation, used when the `pkcs11` build tag IS active.
func NewSigner(opts ...SignerOption) (crypto.Signer, error) {
	// 1. Apply functional options to a default config
	cfg := &signerConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply signer option: %w", err)
		}
	}

	// 2. Route to the correct signer constructor
	switch cfg.module {
	case "", "software":
		_, priv, err := GenerateEd25519KeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key for software signer: %w", err)
		}
		return NewEd25519Signer(priv), nil
	case "pkcs11":
		// Parse PKCS#11 options from cfg.options string
		// Expected format: "module-path=/path/to/lib.so,slot-id=0,label=key-label"
		//
		// SECURITY NOTE: The PIN is passed via cfg.pin and is NOT zeroized by this factory.
		// The underlying PKCS11Signer (from go-platform-signers) is responsible for:
		// 1. Using the PIN only during C_Login
		// 2. Zeroizing the PIN from memory after authentication
		// 3. Closing the PKCS#11 session via Close() method
		pkcs11Config := pkcs11.PKCS11Config{
			PIN: cfg.pin,
		}

		// Parse the options string
		if cfg.options != "" {
			pairs := strings.Split(cfg.options, ",")
			for _, pair := range pairs {
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) != 2 {
					return nil, fmt.Errorf("invalid option format: %s (expected key=value)", pair)
				}
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])

				switch key {
				case "module-path":
					// Validate path before assigning
					if err := validateModulePath(value); err != nil {
						return nil, fmt.Errorf("invalid module-path: %w", err)
					}
					pkcs11Config.ModulePath = value
				case "slot-id":
					slotID, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid slot-id: %w", err)
					}
					// Validate slot ID bounds
					if err := validateSlotID(uint(slotID)); err != nil {
						return nil, err
					}
					pkcs11Config.SlotID = uint(slotID)
				case "label":
					// Validate label before assigning
					if err := validateKeyLabel(value); err != nil {
						return nil, fmt.Errorf("invalid label: %w", err)
					}
					pkcs11Config.KeyLabel = value
				default:
					return nil, fmt.Errorf("unknown pkcs11 option: %s", key)
				}
			}
		}

		// Validate required fields
		if pkcs11Config.ModulePath == "" {
			return nil, fmt.Errorf("pkcs11 module-path is required")
		}
		if pkcs11Config.KeyLabel == "" {
			return nil, fmt.Errorf("pkcs11 key label is required")
		}

		// Create the PKCS#11 signer using go-platform-signers
		return pkcs11.NewPKCS11Signer(pkcs11Config)
	case "touchid":
		return nil, fmt.Errorf("touchid support not compiled in; please build with '-tags touchid' on macOS")
	default:
		return nil, fmt.Errorf("unknown signer module: %s", cfg.module)
	}
}
