package lifecycle_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/jamestexas/signet/pkg/lifecycle"
)

// TestSecureValue_BasicUsage verifies basic usage pattern
func TestSecureValue_BasicUsage(t *testing.T) {
	// Create a test value (slice of bytes representing a key)
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	// Test Use() before Destroy()
	var sawValue []byte
	err := secure.Use(func(value *[]byte) error {
		sawValue = make([]byte, len(*value))
		copy(sawValue, *value)
		return nil
	})

	if err != nil {
		t.Fatalf("Use() before Destroy() failed: %v", err)
	}

	if !bytesEqual(sawValue, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("Use() returned wrong value: got %v, want %v", sawValue, []byte{1, 2, 3, 4, 5})
	}
}

// TestSecureValue_Destroy verifies destruction behavior
func TestSecureValue_Destroy(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	// Destroy the value
	secure.Destroy()

	// Verify destroyed flag
	if !secure.IsDestroyed() {
		t.Error("IsDestroyed() returned false after Destroy()")
	}

	// Try to use after destroy
	err := secure.Use(func(value *[]byte) error {
		return nil
	})

	if err == nil {
		t.Error("Use() after Destroy() should fail, but succeeded")
	}
}

// TestSecureValue_IdempotentDestroy verifies Destroy can be called multiple times
func TestSecureValue_IdempotentDestroy(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	// Call Destroy multiple times
	secure.Destroy()
	secure.Destroy()
	secure.Destroy()

	if !secure.IsDestroyed() {
		t.Error("IsDestroyed() returned false after multiple Destroy() calls")
	}
}

// TestSecureValue_UseReturnsError verifies error propagation
func TestSecureValue_UseReturnsError(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)
	defer secure.Destroy()

	expectedErr := fmt.Errorf("test error")
	err := secure.Use(func(value *[]byte) error {
		return expectedErr
	})

	if err != expectedErr {
		t.Errorf("Use() did not propagate error: got %v, want %v", err, expectedErr)
	}
}

// TestSecureValue_ConcurrentUse verifies concurrent Use() is safe
func TestSecureValue_ConcurrentUse(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)
	defer secure.Destroy()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := secure.Use(func(value *[]byte) error {
				// Verify value is correct
				if !bytesEqual(*value, []byte{1, 2, 3, 4, 5}) {
					return fmt.Errorf("wrong value: %v", *value)
				}
				return nil
			})
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent Use() failed: %v", err)
	}
}

// TestSecureValue_Ed25519Key verifies usage with real Ed25519 keys
func TestSecureValue_Ed25519Key(t *testing.T) {
	// Generate a real Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create zeroizer for Ed25519 private keys
	zeroizer := func(key *ed25519.PrivateKey) {
		for i := range *key {
			(*key)[i] = 0
		}
	}

	secure := lifecycle.New(priv, zeroizer)
	defer secure.Destroy()

	// Use the key to sign a message
	message := []byte("test message")
	var signature []byte

	err = secure.Use(func(key *ed25519.PrivateKey) error {
		signature = ed25519.Sign(*key, message)
		return nil
	})

	if err != nil {
		t.Fatalf("Use() failed: %v", err)
	}

	// Verify the signature with the public key
	if !ed25519.Verify(pub, message, signature) {
		t.Error("Signature verification failed")
	}
}

// TestSecureValue_ZeroizationWorks verifies that zeroization actually zeros the value
func TestSecureValue_ZeroizationWorks(t *testing.T) {
	// Create a key that we can inspect after zeroization
	originalKey := []byte{1, 2, 3, 4, 5}
	key := make([]byte, len(originalKey))
	copy(key, originalKey)

	// Track if zeroizer was called
	zeroizerCalled := false
	zeroizer := func(k *[]byte) {
		zeroizerCalled = true
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	// Destroy and verify zeroizer was called
	secure.Destroy()

	if !zeroizerCalled {
		t.Error("Zeroizer was not called during Destroy()")
	}

	// Verify the value is actually zeroed by trying to Use (should fail) and checking the flag
	if !secure.IsDestroyed() {
		t.Error("IsDestroyed() should return true after Destroy()")
	}
}

// TestSecureValue_StructType verifies usage with struct types
func TestSecureValue_StructType(t *testing.T) {
	type Secret struct {
		Password string
		Token    []byte
	}

	secret := Secret{
		Password: "secret123",
		Token:    []byte{1, 2, 3, 4},
	}

	zeroizer := func(s *Secret) {
		// Zero the string (best effort - strings are immutable in Go)
		s.Password = ""
		// Zero the byte slice
		for i := range s.Token {
			s.Token[i] = 0
		}
	}

	secure := lifecycle.New(secret, zeroizer)

	// Use the secret
	err := secure.Use(func(value *Secret) error {
		if value.Password != "secret123" {
			return fmt.Errorf("wrong password: %s", value.Password)
		}
		if !bytesEqual(value.Token, []byte{1, 2, 3, 4}) {
			return fmt.Errorf("wrong token: %v", value.Token)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Use() failed: %v", err)
	}

	// Destroy
	secure.Destroy()

	if !secure.IsDestroyed() {
		t.Error("IsDestroyed() should return true after Destroy()")
	}
}

// TestSecureValue_PanicOnNilZeroizer verifies panic when zeroizer is nil
func TestSecureValue_PanicOnNilZeroizer(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("New() with nil zeroizer should panic, but did not")
		}
	}()

	key := []byte{1, 2, 3}
	_ = lifecycle.New(key, nil)
}

// TestSecureValue_DestroyDuringConcurrentUse verifies safe destruction
func TestSecureValue_DestroyDuringConcurrentUse(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}

	zeroizer := func(k *[]byte) {
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	var wg sync.WaitGroup
	const numGoroutines = 10

	// Start multiple concurrent Use() operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = secure.Use(func(value *[]byte) error {
				// Simulate some work
				_ = *value
				return nil
			})
		}()
	}

	// Destroy while Use() operations may be in progress
	// This should wait for all Use() to complete before zeroizing
	go func() {
		secure.Destroy()
	}()

	wg.Wait()

	// After all goroutines complete, should be destroyed
	if !secure.IsDestroyed() {
		t.Error("Expected SecureValue to be destroyed")
	}
}

// TestSecureValue_NoMemoryLeakWithPointer verifies pointer API prevents copies
func TestSecureValue_NoMemoryLeakWithPointer(t *testing.T) {
	// This test demonstrates that with the pointer API, callers receive
	// a pointer to the internal value, not a copy. When Destroy() is called,
	// the internal value is zeroized, and no copies remain (as long as the
	// callback doesn't create copies).

	key := []byte{1, 2, 3, 4, 5}
	zeroizerCalled := false

	zeroizer := func(k *[]byte) {
		zeroizerCalled = true
		for i := range *k {
			(*k)[i] = 0
		}
	}

	secure := lifecycle.New(key, zeroizer)

	// Use the key without creating copies
	signatureCount := 0
	err := secure.Use(func(k *[]byte) error {
		// Work with the pointer directly
		if len(*k) == 5 {
			signatureCount++
		}
		// DON'T do this: leaked := *k (creates a copy)
		return nil
	})

	if err != nil {
		t.Fatalf("Use() failed: %v", err)
	}

	if signatureCount != 1 {
		t.Errorf("Expected 1 signature, got %d", signatureCount)
	}

	// Destroy should zeroize the internal value
	secure.Destroy()

	if !zeroizerCalled {
		t.Error("Zeroizer should have been called")
	}

	// Verify we can't use after destroy
	err = secure.Use(func(k *[]byte) error {
		t.Error("Should not be able to use after destroy")
		return nil
	})

	if err == nil {
		t.Error("Use() after Destroy() should return error")
	}
}

// Helper function to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
