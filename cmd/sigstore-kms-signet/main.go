package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
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

	// 1. Try to load from Secure Keyring first
	signer, err := keystore.LoadMasterKeySecure()
	if err != nil {
		// 2. Fallback to Insecure (File-based)
		// We need the home dir for this.
		cfg := config.New(config.DefaultHome())

		signer, err = keystore.LoadMasterKeyInsecure(cfg.Home)
		if err != nil {
			return nil, fmt.Errorf("failed to load signet key: %w", err)
		}
	}

	// 3. Verify the loaded key matches the requested ID
	// The signer.Public() returns the crypto.PublicKey.
	// We need to convert it to the hex ID format signet uses to compare.
	pub := signer.Public()
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("loaded key is not ed25519")
	}

	// signet uses hex-encoded public key as ID
	loadedID := fmt.Sprintf("%x", edPub)

	// Allow "default" or "master" as aliases, or strict match
	if expectedKeyID != "default" && expectedKeyID != "master" && expectedKeyID != loadedID {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", expectedKeyID, loadedID)
	}

	return &SignetKMS{
		signer: signer,
		pubKey: pub,
	}, nil
}

func (s *SignetKMS) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pubKey, nil
}

func (s *SignetKMS) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	data, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}

	// Use the signet signer
	// We use crypto.Signer's Sign method.
	// The explicit 'rand' can be nil for Ed25519
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

	edPub := s.pubKey.(ed25519.PublicKey)
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

func main() {
	args, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		if writeErr := handler.WriteErrorResponse(os.Stdout, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", writeErr)
		}
		os.Exit(1)
	}

	impl, err := NewSignetKMS(args.InitOptions.KeyResourceID)
	if err != nil {
		if writeErr := handler.WriteErrorResponse(os.Stdout, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", writeErr)
		}
		os.Exit(1)
	}

	// Ensure we destroy/zeroize the key on exit (best effort)
	defer impl.signer.Destroy()

	_, err = handler.Dispatch(os.Stdout, os.Stdin, args, impl)
	if err != nil {
		os.Exit(1)
	}
}
