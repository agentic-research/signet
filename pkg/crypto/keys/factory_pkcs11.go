//go:build pkcs11

package keys

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"

	"github.com/jamestexas/go-platform-signers/pkcs11"
)

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
					pkcs11Config.ModulePath = value
				case "slot-id":
					slotID, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid slot-id: %w", err)
					}
					pkcs11Config.SlotID = uint(slotID)
				case "label":
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
	default:
		return nil, fmt.Errorf("unknown signer module: %s", cfg.module)
	}
}
