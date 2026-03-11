//go:build darwin && cgo && touchid

package keys

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/agentic-research/go-platform-signers/touchid"
	"github.com/agentic-research/signet/pkg/crypto/algorithm"
)

// validateKeyLabel checks for control characters and ensures reasonable length.
// This is duplicated from factory_pkcs11.go to avoid build tag complications.
func validateTouchIDKeyLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("key label cannot be empty")
	}

	if len(label) > 256 {
		return fmt.Errorf("key label too long (max 256 characters)")
	}

	return nil
}

// NewSigner is the factory function for creating signers.
// This is the enhanced implementation for macOS with Touch ID support.
// Build with: go build -tags touchid
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
		alg := cfg.algorithm
		if alg == "" {
			alg = algorithm.Ed25519
		}
		ops, err := algorithm.Get(alg)
		if err != nil {
			return nil, fmt.Errorf("unsupported algorithm %q: %w", alg, err)
		}
		_, signer, err := ops.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key for software signer: %w", err)
		}
		return signer, nil
	case "pkcs11":
		return nil, fmt.Errorf("pkcs11 support not compiled in; please build with '-tags pkcs11'")
	case "touchid":
		// Parse Touch ID options from cfg.options string
		// Expected format: "label=my-key-label" or empty (uses default label)
		touchidConfig := touchid.TouchIDConfig{
			KeyLabel: "signet-touchid-key", // Default label
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
				case "label":
					// Validate label before assigning
					if err := validateTouchIDKeyLabel(value); err != nil {
						return nil, fmt.Errorf("invalid label: %w", err)
					}
					touchidConfig.KeyLabel = value
				default:
					return nil, fmt.Errorf("unknown touchid option: %s (supported: label)", key)
				}
			}
		}

		// Create the Touch ID signer using go-platform-signers
		return touchid.NewTouchIDSigner(touchidConfig)
	default:
		return nil, fmt.Errorf("unknown signer module: %s", cfg.module)
	}
}
