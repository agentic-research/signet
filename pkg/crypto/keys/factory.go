//go:build !pkcs11

package keys

import (
	"crypto"
	"fmt"
)

// NewSigner is the factory function for creating signers.
// This is the default implementation, used when the `pkcs11` build tag is NOT active.
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
		return nil, fmt.Errorf("pkcs11 support not compiled in; please build with '-tags pkcs11'")
	default:
		return nil, fmt.Errorf("unknown signer module: %s", cfg.module)
	}
}
