package keys_test

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/jamestexas/signet/pkg/crypto/algorithm"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

// S2: KeyFactory produces crypto.Signer, sign + verify round-trip
func TestKeyFactory_ProducesCryptoSigner_Ed25519(t *testing.T) {
	testKeyFactoryProducesCryptoSigner(t, algorithm.Ed25519)
}

func TestKeyFactory_ProducesCryptoSigner_MLDSA44(t *testing.T) {
	testKeyFactoryProducesCryptoSigner(t, algorithm.MLDSA44)
}

func testKeyFactoryProducesCryptoSigner(t *testing.T, alg algorithm.Algorithm) {
	t.Helper()

	signer, err := keys.NewSigner(keys.WithAlgorithm(alg))
	if err != nil {
		t.Fatalf("NewSigner(%s): %v", alg, err)
	}

	// Verify it implements crypto.Signer
	var _ crypto.Signer = signer

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	message := []byte("factory integration test")
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := algorithm.Verify(pub, message, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("valid signature rejected")
	}
}
