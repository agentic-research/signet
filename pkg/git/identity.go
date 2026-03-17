package git

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentic-research/signet/pkg/cli/config"
	"github.com/agentic-research/signet/pkg/cli/keystore"
	"github.com/agentic-research/signet/pkg/crypto/keys"
)

// Identity represents a signing identity with optional user attribution.
// Level 0: machine identity only (MasterKey).
// Level 1+: machine identity + bridge cert for user attribution.
type Identity struct {
	MasterKey *keys.Ed25519Signer
	MachineID string

	// Optional user attribution (Level 1+)
	BridgeCert *x509.Certificate
	BridgeKey  *keys.SecurePrivateKey
}

// Level returns the identity disclosure level (0 or 1).
func (i *Identity) Level() int {
	if i.BridgeCert == nil {
		return 0
	}
	return 1
}

// HasUserAttribution returns true if a bridge cert is configured.
func (i *Identity) HasUserAttribution() bool {
	return i.BridgeCert != nil && i.BridgeKey != nil
}

// Destroy zeroizes sensitive key material.
func (i *Identity) Destroy() {
	if i.MasterKey != nil {
		i.MasterKey.Destroy()
	}
	if i.BridgeKey != nil {
		i.BridgeKey.Destroy()
	}
}

// LoadIdentity loads the signing identity from configuration.
// It always loads the machine master key (Level 0).
// If bridge cert/key files exist under cfg.Home/git/, they are loaded for Level 1+.
func LoadIdentity(cfg *config.Config) (*Identity, error) {
	masterKey, err := keystore.LoadMasterKeySecure()
	if err != nil {
		if err := cfg.ValidateHomePathRuntime(); err != nil {
			return nil, fmt.Errorf("invalid home directory: %w", err)
		}
		masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			return nil, fmt.Errorf("failed to load master key: %w", err)
		}
	}

	identity := &Identity{
		MasterKey: masterKey,
		MachineID: cfg.IssuerDID,
	}

	// From this point, all error paths must zeroize identity to prevent key leaks.
	// Mirrors the ownershipTransferred pattern from IssueCodeSigningCertificateSecure.
	var ownershipTransferred bool
	defer func() {
		if !ownershipTransferred {
			identity.Destroy()
		}
	}()

	// Try to load bridge cert/key (Level 1+)
	bridgeCertPath := filepath.Join(cfg.Home, "git", "bridge-cert.pem")
	bridgeKeyPath := filepath.Join(cfg.Home, "git", "bridge-key.pem")

	certExists, err := fileAccessible(bridgeCertPath)
	if err != nil {
		return nil, fmt.Errorf("bridge cert inaccessible: %w", err)
	}
	keyExists, err := fileAccessible(bridgeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("bridge key inaccessible: %w", err)
	}
	if !certExists || !keyExists {
		ownershipTransferred = true
		return identity, nil
	}

	identity.BridgeCert, err = loadCertificatePEM(bridgeCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load bridge cert: %w", err)
	}

	identity.BridgeKey, err = loadPrivateKeyPEM(bridgeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load bridge key: %w", err)
	}

	// Verify bridge key matches bridge cert public key
	certPub, ok := identity.BridgeCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bridge cert has non-Ed25519 public key: %T", identity.BridgeCert.PublicKey)
	}
	if !certPub.Equal(identity.BridgeKey.Key().Public()) {
		return nil, fmt.Errorf("bridge key does not match bridge certificate public key")
	}

	ownershipTransferred = true
	return identity, nil
}

// fileAccessible checks if a file exists and is accessible.
// Returns (false, nil) if the file doesn't exist.
// Returns (false, err) if the file exists but is inaccessible (e.g., permission denied).
func fileAccessible(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err // permission error or other issue — don't silently downgrade
}

func loadCertificatePEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKeyPEM(path string) (*keys.SecurePrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Zeroize PEM data when done (contains private key material)
	defer zeroBytes(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	// Zeroize DER data when done
	defer zeroBytes(block.Bytes)

	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edKey, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bridge key must be Ed25519, got %T", raw)
	}
	return keys.NewSecurePrivateKey(edKey), nil
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
