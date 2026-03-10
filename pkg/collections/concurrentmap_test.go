package collections_test

import (
	"fmt"
	"sync"
	"testing"

	// Used for timeout detection in attack tests (deadlock detection)
	"time"

	"github.com/agentic-research/signet/pkg/collections"
)

// TestConcurrentMap_BasicOperations verifies basic get/set/delete
func TestConcurrentMap_BasicOperations(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	// Set a value
	cm.Set("key1", 42)

	// Get the value
	value, ok := cm.Get("key1")
	if !ok {
		t.Fatal("Expected key1 to exist")
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}

	// Delete the value
	cm.Delete("key1")

	// Verify deletion
	_, ok = cm.Get("key1")
	if ok {
		t.Error("Expected key1 to be deleted")
	}
}

// TestConcurrentMap_GetNonExistent verifies getting non-existent keys
func TestConcurrentMap_GetNonExistent(t *testing.T) {
	cm := collections.NewConcurrentMap[string, string]()

	value, ok := cm.Get("nonexistent")
	if ok {
		t.Error("Expected Get to return false for nonexistent key")
	}
	if value != "" {
		t.Errorf("Expected zero value '', got '%s'", value)
	}
}

// TestConcurrentMap_SetOverwrite verifies overwriting values
func TestConcurrentMap_SetOverwrite(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("key", 1)
	cm.Set("key", 2)

	value, _ := cm.Get("key")
	if value != 2 {
		t.Errorf("Expected value 2, got %d", value)
	}
}

// TestConcurrentMap_DeleteNonExistent verifies deleting non-existent keys is safe
func TestConcurrentMap_DeleteNonExistent(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	// Should not panic
	cm.Delete("nonexistent")
}

// TestConcurrentMap_Len verifies length counting
func TestConcurrentMap_Len(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	if cm.Len() != 0 {
		t.Errorf("Expected length 0, got %d", cm.Len())
	}

	cm.Set("key1", 1)
	cm.Set("key2", 2)
	cm.Set("key3", 3)

	if cm.Len() != 3 {
		t.Errorf("Expected length 3, got %d", cm.Len())
	}

	cm.Delete("key2")

	if cm.Len() != 2 {
		t.Errorf("Expected length 2, got %d", cm.Len())
	}
}

// TestConcurrentMap_Has verifies key existence checking
func TestConcurrentMap_Has(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	if cm.Has("key") {
		t.Error("Expected Has to return false for nonexistent key")
	}

	cm.Set("key", 42)

	if !cm.Has("key") {
		t.Error("Expected Has to return true for existing key")
	}

	cm.Delete("key")

	if cm.Has("key") {
		t.Error("Expected Has to return false after deletion")
	}
}

// TestConcurrentMap_Keys verifies key listing
func TestConcurrentMap_Keys(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("a", 1)
	cm.Set("b", 2)
	cm.Set("c", 3)

	keys := cm.Keys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	// Verify all keys are present (order not guaranteed)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}

	if !keySet["a"] || !keySet["b"] || !keySet["c"] {
		t.Errorf("Missing keys in Keys() result: %v", keys)
	}
}

// TestConcurrentMap_ForEach verifies iteration
func TestConcurrentMap_ForEach(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("a", 1)
	cm.Set("b", 2)
	cm.Set("c", 3)

	sum := 0
	count := 0
	cm.ForEach(func(key string, value int) bool {
		sum += value
		count++
		return true
	})

	if count != 3 {
		t.Errorf("Expected to iterate 3 times, got %d", count)
	}
	if sum != 6 {
		t.Errorf("Expected sum 6, got %d", sum)
	}
}

// TestConcurrentMap_ForEachEarlyStop verifies early stopping in iteration
func TestConcurrentMap_ForEachEarlyStop(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("a", 1)
	cm.Set("b", 2)
	cm.Set("c", 3)

	count := 0
	cm.ForEach(func(key string, value int) bool {
		count++
		return count < 2 // Stop after 2 iterations
	})

	if count != 2 {
		t.Errorf("Expected to iterate 2 times, got %d", count)
	}
}

// TestConcurrentMap_Clear verifies clearing the map
func TestConcurrentMap_Clear(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("a", 1)
	cm.Set("b", 2)
	cm.Set("c", 3)

	if cm.Len() != 3 {
		t.Fatalf("Expected length 3, got %d", cm.Len())
	}

	cm.Clear()

	if cm.Len() != 0 {
		t.Errorf("Expected length 0 after Clear, got %d", cm.Len())
	}

	if cm.Has("a") || cm.Has("b") || cm.Has("c") {
		t.Error("Keys should not exist after Clear")
	}
}

// TestConcurrentMap_GetOrSet verifies atomic get-or-set
func TestConcurrentMap_GetOrSet(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	// First GetOrSet should set the value
	value, loaded := cm.GetOrSet("key", 42)
	if loaded {
		t.Error("Expected loaded to be false for first GetOrSet")
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}

	// Second GetOrSet should return existing value
	value, loaded = cm.GetOrSet("key", 100)
	if !loaded {
		t.Error("Expected loaded to be true for second GetOrSet")
	}
	if value != 42 {
		t.Errorf("Expected existing value 42, got %d", value)
	}
}

// TestConcurrentMap_CompareAndDelete verifies conditional deletion
func TestConcurrentMap_CompareAndDelete(t *testing.T) {
	cm := collections.NewConcurrentMap[string, int]()

	cm.Set("key", 42)

	// Try to delete with wrong value
	deleted := cm.CompareAndDelete("key", 100)
	if deleted {
		t.Error("Expected CompareAndDelete to fail with wrong value")
	}

	// Value should still exist
	if !cm.Has("key") {
		t.Error("Key should still exist after failed CompareAndDelete")
	}

	// Delete with correct value
	deleted = cm.CompareAndDelete("key", 42)
	if !deleted {
		t.Error("Expected CompareAndDelete to succeed with correct value")
	}

	// Value should be gone
	if cm.Has("key") {
		t.Error("Key should be deleted after successful CompareAndDelete")
	}
}

// TestConcurrentMap_ConcurrentReads verifies concurrent reads are safe
func TestConcurrentMap_ConcurrentReads(t *testing.T) {
	cm := collections.NewConcurrentMap[int, string]()

	// Populate map
	for i := 0; i < 100; i++ {
		cm.Set(i, fmt.Sprintf("value%d", i))
	}

	// Concurrent reads
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errCh := make(chan error, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				value, ok := cm.Get(i)
				if !ok {
					errCh <- fmt.Errorf("key %d not found", i)
					return
				}
				expected := fmt.Sprintf("value%d", i)
				if value != expected {
					errCh <- fmt.Errorf("wrong value for key %d: got %s, want %s", i, value, expected)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

// TestConcurrentMap_ConcurrentWrites verifies concurrent writes are safe
// Run with: go test -race
func TestConcurrentMap_ConcurrentWrites(t *testing.T) {
	cm := collections.NewConcurrentMap[int, int]()

	const numGoroutines = 50
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				key := id*writesPerGoroutine + i
				cm.Set(key, key)
			}
		}(g)
	}

	wg.Wait()

	// Verify all writes succeeded
	expectedCount := numGoroutines * writesPerGoroutine
	if cm.Len() != expectedCount {
		t.Errorf("Expected %d entries, got %d", expectedCount, cm.Len())
	}
}

// TestConcurrentMap_ConcurrentReadWrite verifies mixed read/write operations
// Run with: go test -race
func TestConcurrentMap_ConcurrentReadWrite(t *testing.T) {
	cm := collections.NewConcurrentMap[int, int]()

	// Pre-populate
	for i := 0; i < 100; i++ {
		cm.Set(i, i)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // readers + writers

	// Readers
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				cm.Get(i % 100)
			}
		}()
	}

	// Writers
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				key := i % 100
				cm.Set(key, key*2)
			}
		}(g)
	}

	wg.Wait()
}

// TestConcurrentMap_ConcurrentDelete verifies concurrent deletions
// Run with: go test -race
func TestConcurrentMap_ConcurrentDelete(t *testing.T) {
	cm := collections.NewConcurrentMap[int, int]()

	// Populate
	const numEntries = 1000
	for i := 0; i < numEntries; i++ {
		cm.Set(i, i)
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Each goroutine deletes a different range
	entriesPerGoroutine := numEntries / numGoroutines
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			start := id * entriesPerGoroutine
			end := start + entriesPerGoroutine
			for i := start; i < end; i++ {
				cm.Delete(i)
			}
		}(g)
	}

	wg.Wait()

	if cm.Len() != 0 {
		t.Errorf("Expected all entries deleted, but %d remain", cm.Len())
	}
}

// TestConcurrentMap_PointerValues verifies usage with pointer values
func TestConcurrentMap_PointerValues(t *testing.T) {
	type Record struct {
		ID   string
		Data int
	}

	cm := collections.NewConcurrentMap[string, *Record]()

	record := &Record{ID: "test", Data: 42}
	cm.Set("key", record)

	retrieved, ok := cm.Get("key")
	if !ok {
		t.Fatal("Expected key to exist")
	}

	if retrieved.ID != "test" || retrieved.Data != 42 {
		t.Errorf("Record mismatch: got %+v", retrieved)
	}

	// Verify it's the same pointer
	if retrieved != record {
		t.Error("Expected to get the same pointer back")
	}
}

// TestConcurrentMap_IntegerKeys verifies usage with integer keys
func TestConcurrentMap_IntegerKeys(t *testing.T) {
	cm := collections.NewConcurrentMap[int, string]()

	cm.Set(1, "one")
	cm.Set(2, "two")
	cm.Set(3, "three")

	value, ok := cm.Get(2)
	if !ok || value != "two" {
		t.Errorf("Expected 'two', got '%s', ok=%v", value, ok)
	}
}

// TestConcurrentMap_CompareAndDeleteFunc verifies custom comparator
func TestConcurrentMap_CompareAndDeleteFunc(t *testing.T) {
	type Record struct {
		ID   string
		Data int
	}

	cm := collections.NewConcurrentMap[string, Record]()

	record := Record{ID: "test", Data: 42}
	cm.Set("key", record)

	// CompareAndDelete would fail for structs due to any() comparison
	// But CompareAndDeleteFunc should work
	equal := func(a, b Record) bool {
		return a.ID == b.ID && a.Data == b.Data
	}

	deleted := cm.CompareAndDeleteFunc("key", Record{ID: "test", Data: 42}, equal)
	if !deleted {
		t.Error("Expected CompareAndDeleteFunc to succeed with matching struct")
	}

	if cm.Has("key") {
		t.Error("Key should be deleted after successful CompareAndDeleteFunc")
	}
}

// TestConcurrentMap_CompareAndDeleteFunc_NoMatch verifies non-matching deletion fails
func TestConcurrentMap_CompareAndDeleteFunc_NoMatch(t *testing.T) {
	type Record struct {
		ID   string
		Data int
	}

	cm := collections.NewConcurrentMap[string, Record]()

	cm.Set("key", Record{ID: "test", Data: 42})

	equal := func(a, b Record) bool {
		return a.ID == b.ID && a.Data == b.Data
	}

	// Try to delete with wrong data
	deleted := cm.CompareAndDeleteFunc("key", Record{ID: "test", Data: 99}, equal)
	if deleted {
		t.Error("Expected CompareAndDeleteFunc to fail with non-matching struct")
	}

	if !cm.Has("key") {
		t.Error("Key should still exist after failed CompareAndDeleteFunc")
	}
}

// TestConcurrentMap_ForEachCanCallMethods verifies ForEach no longer deadlocks
func TestConcurrentMap_ForEachCanCallMethods(t *testing.T) {
	cm := collections.NewConcurrentMap[int, int]()

	// Populate map
	for i := 0; i < 10; i++ {
		cm.Set(i, i*2)
	}

	// This used to deadlock, but now works because ForEach uses a snapshot
	deleted := 0
	cm.ForEach(func(key, value int) bool {
		if value > 10 {
			cm.Delete(key) // Safe now!
			deleted++
		}
		return true
	})

	if deleted == 0 {
		t.Error("Expected some deletions to occur")
	}

	// Verify deletions worked
	finalLen := cm.Len()
	if finalLen >= 10 {
		t.Errorf("Expected fewer than 10 entries after deletion, got %d", finalLen)
	}
}

// TestConcurrentMap_AttackForEachDeadlock demonstrates the deadlock vulnerability
// This test would DEADLOCK with the old implementation (holding RLock during callback).
// With the new snapshot approach, it completes successfully.
//
// NOTE: This test uses a timeout to detect deadlock instead of actually deadlocking,
// because we want the test suite to pass :)
func TestConcurrentMap_AttackForEachDeadlock(t *testing.T) {
	t.Run("old_implementation_would_deadlock", func(t *testing.T) {
		cm := collections.NewConcurrentMap[string, int]()

		cm.Set("key1", 1)
		cm.Set("key2", 2)
		cm.Set("key3", 3)

		// ATTACK: Try to cause deadlock by calling Delete during ForEach
		// Old implementation: ForEach holds RLock, Delete tries to acquire Lock -> DEADLOCK
		// New implementation: ForEach uses snapshot, no locks held during callback -> SUCCESS

		done := make(chan bool, 1)

		go func() {
			cm.ForEach(func(key string, value int) bool {
				// This would deadlock in old implementation
				cm.Delete(key)
				return true
			})
			done <- true
		}()

		// Wait with timeout
		select {
		case <-done:
			t.Log("✓ ForEach with Delete completed without deadlock")
		case <-time.After(2 * time.Second):
			t.Fatal("DEADLOCK DETECTED: ForEach with Delete timed out")
		}
	})

	t.Run("multiple_concurrent_operations_during_foreach", func(t *testing.T) {
		cm := collections.NewConcurrentMap[int, string]()

		// Populate
		for i := 0; i < 100; i++ {
			cm.Set(i, fmt.Sprintf("value%d", i))
		}

		// ATTACK: Perform multiple dangerous operations during ForEach
		done := make(chan bool, 1)

		go func() {
			cm.ForEach(func(key int, value string) bool {
				// All of these would cause deadlock with old implementation
				cm.Get(key % 50)        // RLock during RLock (ok)
				cm.Set(key+1000, "new") // Lock during RLock (DEADLOCK in old)
				cm.Delete(key % 10)     // Lock during RLock (DEADLOCK in old)
				cm.Has(key)             // RLock during RLock (ok)
				return true
			})
			done <- true
		}()

		select {
		case <-done:
			t.Log("✓ Complex operations during ForEach completed without deadlock")
		case <-time.After(2 * time.Second):
			t.Fatal("DEADLOCK DETECTED: Complex ForEach operations timed out")
		}
	})

	t.Run("nested_foreach_calls", func(t *testing.T) {
		cm := collections.NewConcurrentMap[int, int]()

		for i := 0; i < 10; i++ {
			cm.Set(i, i*2)
		}

		// ATTACK: Nest ForEach calls
		// Old implementation: Outer ForEach holds RLock, inner ForEach tries RLock -> DEADLOCK
		// New implementation: Each ForEach uses independent snapshot -> SUCCESS

		done := make(chan bool, 1)

		go func() {
			count := 0
			cm.ForEach(func(key1, value1 int) bool {
				// Nested ForEach would deadlock in old implementation
				cm.ForEach(func(key2, value2 int) bool {
					count++
					return true
				})
				return true
			})
			done <- true
		}()

		select {
		case <-done:
			t.Log("✓ Nested ForEach completed without deadlock")
		case <-time.After(2 * time.Second):
			t.Fatal("DEADLOCK DETECTED: Nested ForEach timed out")
		}
	})
}
