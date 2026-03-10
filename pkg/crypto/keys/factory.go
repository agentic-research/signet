//go:build !pkcs11

package keys

import (
	"crypto"
	"fmt"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
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
		return nil, fmt.Errorf("touchid support not compiled in; please build with '-tags touchid' on macOS")
	default:
		return nil, fmt.Errorf("unknown signer module: %s", cfg.module)
	}
}
