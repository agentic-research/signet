package collections

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLRUCache_GetOrPut_Absent(t *testing.T) {
	c := NewLRUCache(10)
	val, existed := c.GetOrPut("key1", "value1")
	assert.False(t, existed)
	assert.Nil(t, val)
	assert.Equal(t, 1, c.Len())

	// Verify the value was inserted
	got, ok := c.Get("key1")
	require.True(t, ok)
	assert.Equal(t, "value1", got)
}

func TestLRUCache_GetOrPut_Present(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("key1", "original")

	val, existed := c.GetOrPut("key1", "replacement")
	assert.True(t, existed)
	assert.Equal(t, "original", val)

	// Value should not have been replaced
	got, _ := c.Get("key1")
	assert.Equal(t, "original", got)
}

func TestLRUCache_GetOrPut_Concurrent(t *testing.T) {
	c := NewLRUCache(10)
	const goroutines = 100

	var wg sync.WaitGroup
	wins := make(chan bool, goroutines)

	// All goroutines race to insert the same key
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, existed := c.GetOrPut("race-key", fmt.Sprintf("writer-%d", id))
			wins <- !existed // true if this goroutine "won" the insert
		}(i)
	}
	wg.Wait()
	close(wins)

	// Exactly one goroutine should have won
	winCount := 0
	for won := range wins {
		if won {
			winCount++
		}
	}
	assert.Equal(t, 1, winCount, "exactly one goroutine should win the insert race")
	assert.Equal(t, 1, c.Len())
}

func TestLRUCache_GetOrPut_Eviction(t *testing.T) {
	c := NewLRUCache(2)
	c.GetOrPut("a", 1)
	c.GetOrPut("b", 2)

	// This should evict "a"
	c.GetOrPut("c", 3)

	_, ok := c.Get("a")
	assert.False(t, ok, "oldest entry should be evicted")

	_, ok = c.Get("c")
	assert.True(t, ok, "newest entry should exist")
}
