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
//	// Use the key safely
//	err := secureKey.Use(func(key ed25519.PrivateKey) error {
//		signature := ed25519.Sign(key, message)
//		return nil
//	})
type SecureValue[T any] struct {
	mu        sync.RWMutex
	value     T
	zeroizer  Zeroizer[T]
	destroyed bool
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
// The callback function f receives the value and can perform operations on it.
// Use() ensures that the value cannot be accessed after Destroy() is called.
//
// Use() is safe for concurrent calls from multiple goroutines.
// However, callers MUST ensure Destroy() is not called while Use() operations
// are in progress.
func (s *SecureValue[T]) Use(f func(value T) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return fmt.Errorf("cannot use destroyed SecureValue")
	}

	return f(s.value)
}

// Destroy securely zeros the wrapped value and marks it as destroyed.
// After calling Destroy, all subsequent Use() calls will fail.
//
// Destroy is idempotent - calling it multiple times is safe.
// However, callers MUST ensure no Use() operations are in progress when
// calling Destroy().
//
// Example with proper synchronization:
//
//	var wg sync.WaitGroup
//	wg.Add(2)
//	go func() { defer wg.Done(); secureKey.Use(...) }()
//	go func() { defer wg.Done(); secureKey.Use(...) }()
//	wg.Wait()
//	secureKey.Destroy()
func (s *SecureValue[T]) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.destroyed {
		s.zeroizer(&s.value)
		s.destroyed = true
	}
}

// IsDestroyed returns true if Destroy() has been called.
// This is primarily useful for testing and debugging.
func (s *SecureValue[T]) IsDestroyed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.destroyed
}
