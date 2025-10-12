// Package collections provides generic, thread-safe data structures.
package collections

import "sync"

// ConcurrentMap is a generic, thread-safe map implementation.
// It uses an internal sync.RWMutex to provide concurrent access safety.
//
// Type parameters:
//   - K must be comparable (usable as a map key)
//   - V can be any type
//
// Example usage:
//
//	cm := collections.NewConcurrentMap[string, *TokenRecord]()
//	cm.Set("token123", record)
//	value, ok := cm.Get("token123")
//	cm.Delete("token123")
//
// ConcurrentMap is safe for concurrent use by multiple goroutines.
// All operations are atomic and protected by the internal mutex.
type ConcurrentMap[K comparable, V any] struct {
	mu   sync.RWMutex
	data map[K]V
}

// NewConcurrentMap creates a new empty ConcurrentMap.
func NewConcurrentMap[K comparable, V any]() *ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		data: make(map[K]V),
	}
}

// Get retrieves a value from the map.
// Returns the value and true if the key exists, zero value and false otherwise.
//
// This operation acquires a read lock, allowing multiple concurrent reads.
func (m *ConcurrentMap[K, V]) Get(key K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	value, ok := m.data[key]
	return value, ok
}

// Set stores a key-value pair in the map.
// If the key already exists, its value is updated.
//
// This operation acquires a write lock, blocking other writes and reads.
func (m *ConcurrentMap[K, V]) Set(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = value
}

// Delete removes a key from the map.
// If the key doesn't exist, this is a no-op.
//
// This operation acquires a write lock, blocking other writes and reads.
func (m *ConcurrentMap[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
}

// Len returns the number of items in the map.
//
// This operation acquires a read lock.
func (m *ConcurrentMap[K, V]) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.data)
}

// Has checks if a key exists in the map.
//
// This operation acquires a read lock.
func (m *ConcurrentMap[K, V]) Has(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[key]
	return ok
}

// Keys returns a slice of all keys in the map.
// The returned slice is a snapshot; modifications to the map won't affect it.
//
// This operation acquires a read lock for the duration of the key copy.
func (m *ConcurrentMap[K, V]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]K, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys
}

// ForEach applies a function to each key-value pair in the map.
// The callback receives a point-in-time snapshot of the map, so it's safe
// to call other ConcurrentMap methods from within the callback without deadlock.
//
// Note: The callback sees a snapshot taken at the time ForEach is called.
// Concurrent modifications during iteration won't be visible to the callback.
//
// If the function returns false, iteration stops early.
//
// This operation copies the map entries, so it uses O(n) memory.
func (m *ConcurrentMap[K, V]) ForEach(fn func(key K, value V) bool) {
	// Create a snapshot to avoid holding the lock during callback execution
	m.mu.RLock()
	snapshot := make(map[K]V, len(m.data))
	for k, v := range m.data {
		snapshot[k] = v
	}
	m.mu.RUnlock()

	// Iterate over snapshot without holding any locks
	for k, v := range snapshot {
		if !fn(k, v) {
			break
		}
	}
}

// Clear removes all entries from the map.
//
// This operation acquires a write lock.
func (m *ConcurrentMap[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create a new map instead of deleting entries one by one
	m.data = make(map[K]V)
}

// GetOrSet atomically gets a value if it exists, or sets and returns the provided value.
// Returns the value (either existing or newly set) and true if the value was already present.
//
// This operation acquires a write lock.
func (m *ConcurrentMap[K, V]) GetOrSet(key K, value V) (actual V, loaded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.data[key]; ok {
		return existing, true
	}

	m.data[key] = value
	return value, false
}

// CompareAndDelete deletes a key only if its value matches the expected value.
// Returns true if the key was deleted, false otherwise.
//
// IMPORTANT: This uses direct == comparison after type erasure via any().
// - Works correctly for: basic types (int, string, bool), pointers
// - Does NOT work reliably for: structs, slices, maps, arrays
// - For complex types, use CompareAndDeleteFunc() instead.
//
// This operation acquires a write lock.
func (m *ConcurrentMap[K, V]) CompareAndDelete(key K, expected V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if actual, ok := m.data[key]; ok {
		// Note: This uses type erasure comparison which has limitations.
		// For complex types requiring deep equality, use CompareAndDeleteFunc.
		if any(actual) == any(expected) {
			delete(m.data, key)
			return true
		}
	}

	return false
}

// CompareAndDeleteFunc deletes a key only if its value matches according to
// the provided equality function. Returns true if the key was deleted, false otherwise.
//
// This variant allows custom comparison logic for complex types like structs,
// where deep equality checking is required.
//
// Example:
//
//	type Record struct { ID string; Data int }
//	equal := func(a, b Record) bool { return a.ID == b.ID && a.Data == b.Data }
//	cm.CompareAndDeleteFunc("key", expected, equal)
//
// This operation acquires a write lock.
func (m *ConcurrentMap[K, V]) CompareAndDeleteFunc(key K, expected V, equal func(a, b V) bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if actual, ok := m.data[key]; ok {
		if equal(actual, expected) {
			delete(m.data, key)
			return true
		}
	}

	return false
}
