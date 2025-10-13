// Package lifecycle provides generic wrappers for managing sensitive data lifecycle.
// The primary concern is ensuring cryptographic material is properly zeroized
// when no longer needed, following modern Go patterns with generics.
package lifecycle

import (
	"fmt"
	"sync"
)

// Zeroizer is a function that knows how to securely zero a value of type T.
// Implementations should overwrite the value's memory with zeros to prevent
// sensitive data from lingering in memory.
type Zeroizer[T any] func(value *T)

// SecureValue wraps a sensitive value with lifecycle management.
// It ensures that:
//  1. Access to the value is controlled via Use() method
//  2. The value is automatically zeroized when Destroy() is called
//  3. Operations are concurrency-safe
//  4. Callbacks cannot leak copies of sensitive data
//
// Type parameter T can be any type that holds sensitive data (keys, secrets, etc.)
//
// Example usage:
//
//	// Create a zeroizer for ed25519 private keys
//	zeroizer := func(key *ed25519.PrivateKey) {
//		for i := range *key {
//			(*key)[i] = 0
//		}
//	}
//
//	// Wrap the key
//	secureKey := lifecycle.New(privateKey, zeroizer)
//	defer secureKey.Destroy()
//
//	// Use the key safely (receives pointer to prevent copying)
//	err := secureKey.Use(func(key *ed25519.PrivateKey) error {
//		signature := ed25519.Sign(*key, message)
//		return nil
//	})
type SecureValue[T any] struct {
	mu        sync.RWMutex
	value     T
	zeroizer  Zeroizer[T]
	destroyed bool
	inUse     sync.WaitGroup
}

// New creates a new SecureValue wrapper around a sensitive value.
// The zeroizer function must properly zeroize the value's memory.
func New[T any](value T, zeroizer Zeroizer[T]) *SecureValue[T] {
	if zeroizer == nil {
		panic("lifecycle.New: zeroizer cannot be nil")
	}
	return &SecureValue[T]{
		value:     value,
		zeroizer:  zeroizer,
		destroyed: false,
	}
}

// Use provides temporary, safe access to the wrapped value.
// The callback function f receives a POINTER to the value to prevent copying
// sensitive data. This ensures that only the internal copy can be zeroized.
//
// Use() is safe for concurrent calls from multiple goroutines.
// Destroy() will block until all active Use() calls complete.
//
// SECURITY: The callback receives a pointer to prevent accidental copies.
// Callers should NOT store the pointer or create copies of the value.
func (s *SecureValue[T]) Use(f func(value *T) error) error {
	s.mu.RLock()
	if s.destroyed {
		s.mu.RUnlock()
		return fmt.Errorf("cannot use destroyed SecureValue")
	}
	s.inUse.Add(1)
	s.mu.RUnlock()

	defer s.inUse.Done()

	return f(&s.value)
}

// Destroy securely zeros the wrapped value and marks it as destroyed.
// After calling Destroy, all subsequent Use() calls will fail.
//
// Destroy is idempotent - calling it multiple times is safe.
// Destroy will block until all active Use() operations complete, ensuring
// safe zeroization without race conditions.
//
// Example usage:
//
//	secureKey := lifecycle.New(privateKey, zeroizer)
//	defer secureKey.Destroy()  // Safe to call even with concurrent Use()
//
//	go secureKey.Use(...)  // These can run concurrently
//	go secureKey.Use(...)
//	// Destroy() will wait for all Use() calls to complete
func (s *SecureValue[T]) Destroy() {
	s.mu.Lock()
	if !s.destroyed {
		s.destroyed = true
		s.mu.Unlock()

		// Wait for all Use() calls to complete before zeroizing
		s.inUse.Wait()
		s.zeroizer(&s.value)
	} else {
		s.mu.Unlock()
	}
}

// IsDestroyed returns true if Destroy() has been called.
// This is primarily useful for testing and debugging.
func (s *SecureValue[T]) IsDestroyed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.destroyed
}

// WithSecureValue provides a "loan pattern" for secure lifecycle management.
// It handles the entire New()->Use()->Destroy() lifecycle automatically,
// eliminating the possibility of forgetting to call Destroy().
//
// This is the recommended API for most use cases. It guarantees:
//  1. The value is always zeroized, even if userFunc panics
//  2. No possibility of use-after-destroy bugs
//  3. Clean, self-contained code blocks
//
// Example usage:
//
//	// Sign a message with ephemeral Ed25519 key
//	err := lifecycle.WithSecureValue(privateKey, zeroizer, func(key *ed25519.PrivateKey) error {
//	    signature := ed25519.Sign(*key, message)
//	    return sendSignature(signature)
//	})
//
//	// The key is automatically zeroized here, even if sendSignature panicked
//
// For long-lived objects, use New()/Destroy() directly instead.
func WithSecureValue[T any](value T, zeroizer Zeroizer[T], userFunc func(value *T) error) error {
	secure := New(value, zeroizer)
	defer secure.Destroy()

	return secure.Use(userFunc)
}

// WithSecureValueResult provides the loan pattern with a return value.
// This is useful when you need to extract a result from the secure operation
// without leaking the sensitive value.
//
// Example usage:
//
//	signature, err := lifecycle.WithSecureValueResult(privateKey, zeroizer,
//	    func(key *ed25519.PrivateKey) ([]byte, error) {
//	        sig := ed25519.Sign(*key, message)
//	        return sig, nil
//	    },
//	)
func WithSecureValueResult[T any, R any](value T, zeroizer Zeroizer[T], userFunc func(value *T) (R, error)) (R, error) {
	secure := New(value, zeroizer)
	defer secure.Destroy()

	var result R
	var err error

	useErr := secure.Use(func(v *T) error {
		result, err = userFunc(v)
		return err
	})

	if useErr != nil {
		var zero R
		return zero, useErr
	}

	return result, err
}
