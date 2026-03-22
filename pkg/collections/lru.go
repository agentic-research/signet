package collections

import (
	"container/list"
	"sync"
)

// LRUCache is a thread-safe, fixed-size LRU cache.
type LRUCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	cache    map[interface{}]*list.Element
}

// entry is the type stored in the doubly-linked list.
type entry struct {
	key   interface{}
	value interface{}
}

// NewLRUCache creates a new LRUCache with the given capacity.
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		ll:       list.New(),
		cache:    make(map[interface{}]*list.Element),
	}
}

// Get retrieves a value from the cache.
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.ll.MoveToFront(elem)
		return elem.Value.(*entry).value, true
	}
	return nil, false
}

// Put adds a value to the cache.
func (c *LRUCache) Put(key, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.ll.MoveToFront(elem)
		elem.Value.(*entry).value = value
		return
	}

	if c.ll.Len() >= c.capacity {
		c.evict()
	}

	elem := c.ll.PushFront(&entry{key, value})
	c.cache[key] = elem
}

// evict removes the least recently used item from the cache.
func (c *LRUCache) evict() {
	// This function is not thread-safe and must be called from within a locked mutex.
	elem := c.ll.Back()
	if elem != nil {
		c.ll.Remove(elem)
		delete(c.cache, elem.Value.(*entry).key)
	}
}

// Len returns the number of items in the cache.
func (c *LRUCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Range iterates over the cache and calls the given function for each key and value.
func (c *LRUCache) Range(f func(key, value interface{}) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for elem := c.ll.Front(); elem != nil; elem = elem.Next() {
		ent := elem.Value.(*entry)
		if !f(ent.key, ent.value) {
			break
		}
	}
}

// GetOrPut atomically checks for a key and inserts it if absent.
// Returns (existing value, true) if the key existed, or (nil, false) after inserting.
// This prevents TOCTOU races between separate Get + Put calls.
func (c *LRUCache) GetOrPut(key, value interface{}) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.ll.MoveToFront(elem)
		return elem.Value.(*entry).value, true
	}

	if c.ll.Len() >= c.capacity {
		c.evict()
	}

	elem := c.ll.PushFront(&entry{key, value})
	c.cache[key] = elem
	return nil, false
}

// Delete removes an entry from the cache.
func (c *LRUCache) Delete(key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		c.ll.Remove(elem)
		delete(c.cache, key)
	}
}
