package keys

import (
	"fmt"
	"time"
)

// internal configuration struct for the signer factory.
// It is unexported to force the use of functional options.
type signerConfig struct {
	module   string
	options  string
	pin      string
	validity time.Duration
}

// A SignerOption configures a Signer.
type SignerOption func(*signerConfig) error

// WithModule specifies which signer implementation to use.
// Valid values: "software" (default), "pkcs11".
func WithModule(module string) SignerOption {
	return func(c *signerConfig) error {
		c.module = module
		return nil
	}
}

// WithValidity sets the desired certificate validity duration.
func WithValidity(d time.Duration) SignerOption {
	return func(c *signerConfig) error {
		if d <= 0 {
			return fmt.Errorf("validity duration must be positive")
		}
		c.validity = d
		return nil
	}
}

// WithOptions provides module-specific configuration as an opaque string.
func WithOptions(opts string) SignerOption {
	return func(c *signerConfig) error {
		c.options = opts
		return nil
	}
}

// WithPIN provides the PIN for hardware-backed signers.
func WithPIN(pin string) SignerOption {
	return func(c *signerConfig) error {
		c.pin = pin
		return nil
	}
}
