package cabundle

import (
	"context"
	"sync"
	"time"

	"github.com/jamestexas/signet/pkg/revocation/types"
)

// BundleCache is a simple in-memory cache for CA bundles.
type BundleCache struct {
	mu      sync.RWMutex
	bundles map[string]*cachedBundle
	ttl     time.Duration
}

// cachedBundle is a wrapper around a CA bundle that includes an expiration time.
type cachedBundle struct {
	bundle    *types.CABundle
	expiresAt time.Time
}

// NewBundleCache creates a new BundleCache.
func NewBundleCache(ttl time.Duration) *BundleCache {
	return &BundleCache{
		bundles: make(map[string]*cachedBundle),
		ttl:     ttl,
	}
}

// Get returns a CA bundle from the cache or fetches it if it's not present or expired.
func (c *BundleCache) Get(ctx context.Context, issuerID string, fetcher types.Fetcher) (*types.CABundle, error) {
	// First check with read lock
	c.mu.RLock()
	if cached, ok := c.bundles[issuerID]; ok && time.Now().Before(cached.expiresAt) {
		c.mu.RUnlock()
		return cached.bundle, nil
	}
	c.mu.RUnlock()

	// Upgrade to write lock to prevent double-fetch race condition
	c.mu.Lock()

	// Double-check after acquiring write lock (another goroutine might have fetched it)
	if cached, ok := c.bundles[issuerID]; ok && time.Now().Before(cached.expiresAt) {
		c.mu.Unlock()
		return cached.bundle, nil
	}

	// We hold the write lock, release it before the potentially slow fetch operation
	c.mu.Unlock()

	// Fetch the bundle (outside the lock to avoid blocking other reads)
	bundle, err := fetcher.Fetch(ctx, issuerID)
	if err != nil {
		return nil, err
	}

	// Re-acquire write lock to store the bundle
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundles[issuerID] = &cachedBundle{
		bundle:    bundle,
		expiresAt: time.Now().Add(c.ttl),
	}

	return bundle, nil
}
