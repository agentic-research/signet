package main

// Package main implements a Sigstore KMS plugin that bridges Sigstore tools
// (cosign, gitsign) to Signet's local key management system.
//
// Security model:
// - Private keys are loaded from OS keyring (preferred) or ~/.signet/master.key
// - Keys are zeroized on program exit via deferred Destroy()
// - Plugin protocol communication via stdin/stdout per Sigstore KMS spec
//
// URI scheme: signet://<key-id> where key-id can be:
//   - "default" or "master": loads the primary Signet master key
//   - hex-encoded public key: loads specific key matching that ID

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jamestexas/signet/pkg/cli/config"
	"github.com/jamestexas/signet/pkg/cli/keystore"
	"github.com/jamestexas/signet/pkg/crypto/keys"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

// SignetKMS implements the kms.SignerVerifier interface
type SignetKMS struct {
	signer *keys.Ed25519Signer
	pubKey crypto.PublicKey
}

// NewSignetKMS initializes your signer based on the URI
func NewSignetKMS(resourceID string) (*SignetKMS, error) {
	if !strings.HasPrefix(resourceID, "signet://") {
		return nil, fmt.Errorf("invalid scheme, expected signet://")
	}
	expectedKeyID := strings.TrimPrefix(resourceID, "signet://")

	// Validate key ID: must be a known alias or valid hex string
	if expectedKeyID == "" {
		return nil, fmt.Errorf("empty key ID: use signet://default, signet://master, or signet://<hex-key-id>")
	}
	switch expectedKeyID {
	case "default", "master":
		// known aliases, OK
	default:
		if _, err := hex.DecodeString(expectedKeyID); err != nil {
			return nil, fmt.Errorf("invalid key ID format: must be 'default', 'master', or hex-encoded key ID")
		}
	}

	// 1. Try to load from Secure Keyring first
	signer, err := keystore.LoadMasterKeySecure()
	if err != nil {
		// 2. Fallback to Insecure (File-based)
		fmt.Fprintf(os.Stderr, "Warning: Secure keyring unavailable, falling back to file-based key storage\n")
		cfg := config.New(config.DefaultHome())

		signer, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			return nil, fmt.Errorf("failed to load signet key: %w", err)
		}
	}

	// 3. Verify the loaded key matches the requested ID
	pub := signer.Public()
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		signer.Destroy()
		return nil, fmt.Errorf("loaded key is not ed25519")
	}

	// signet uses hex-encoded public key as ID
	loadedID := fmt.Sprintf("%x", edPub)

	// Allow "default" or "master" as aliases, or constant-time hex match
	isAlias := expectedKeyID == "default" || expectedKeyID == "master"
	isMatch := subtle.ConstantTimeCompare([]byte(expectedKeyID), []byte(loadedID)) == 1

	if !isAlias && !isMatch {
		signer.Destroy()
		// Truncate IDs to avoid leaking full key in logs
		expShort := expectedKeyID
		if len(expShort) > 16 {
			expShort = expShort[:16] + "..."
		}
		loadedShort := loadedID
		if len(loadedShort) > 16 {
			loadedShort = loadedShort[:16] + "..."
		}
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", expShort, loadedShort)
	}

	return &SignetKMS{
		signer: signer,
		pubKey: pub,
	}, nil
}

// Destroy zeros the private key material.
func (s *SignetKMS) Destroy() {
	if s.signer != nil {
		s.signer.Destroy()
	}
}

func (s *SignetKMS) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pubKey, nil
}

// maxSignMessageSize is the maximum message size accepted for signing (10 MB).
// KMS plugin messages are digests or small manifests; this prevents accidental OOM.
const maxSignMessageSize = 10 << 20

func (s *SignetKMS) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	limited := io.LimitReader(message, maxSignMessageSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSignMessageSize {
		return nil, fmt.Errorf("message too large: exceeds %d bytes", maxSignMessageSize)
	}

	return s.signer.Sign(nil, data, crypto.Hash(0))
}

func (s *SignetKMS) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	// Sigstore's default verification logic will handle this if we return a valid PublicKey.
	// However, the interface requires implementation.
	// We can manually verify using the public key we have.

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}

	edPub, ok := s.pubKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ed25519.PublicKey")
	}

	if !ed25519.Verify(edPub, msgBytes, sigBytes) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (s *SignetKMS) DefaultAlgorithm() string {
	return "ed25519"
}

func (s *SignetKMS) SupportedAlgorithms() []string {
	return []string{"ed25519"}
}

func (s *SignetKMS) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("CreateKey not supported by this plugin")
}

func (s *SignetKMS) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	return s.signer, crypto.Hash(0), nil
}

// run contains the main logic, separated from main() so that deferred
// cleanup (key zeroization) executes before os.Exit.
func run() error {
	args, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		if writeErr := handler.WriteErrorResponse(os.Stdout, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", writeErr)
		}
		return err
	}

	impl, err := NewSignetKMS(args.InitOptions.KeyResourceID)
	if err != nil {
		if writeErr := handler.WriteErrorResponse(os.Stdout, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", writeErr)
		}
		return err
	}
	defer impl.Destroy()

	_, err = handler.Dispatch(os.Stdout, os.Stdin, args, impl)
	return err
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
