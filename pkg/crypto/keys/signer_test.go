package keys_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/keys"
)

func TestEd25519SignerConcurrency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := keys.NewEd25519Signer(priv)

	var wg sync.WaitGroup
	errorChan := make(chan error, 100)

	// Spawn 50 goroutines signing concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := []byte("test message")
			sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
			if err != nil {
				errorChan <- err
				return
			}
			if !ed25519.Verify(pub, msg, sig) {
				errorChan <- fmt.Errorf("invalid signature")
			}
		}()
	}

	// Destroy while signing is happening
	time.Sleep(1 * time.Millisecond)
	signer.Destroy()

	wg.Wait()
	close(errorChan)

	// Some goroutines should fail with "destroyed" error
	// None should produce invalid signatures
	for err := range errorChan {
		if !strings.Contains(err.Error(), "signer has been destroyed") {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}
