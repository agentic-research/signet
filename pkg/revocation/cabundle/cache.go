package cabundle

import (
	"context"
	"sync"
	"time"

	"github.com/agentic-research/signet/pkg/revocation/types"
	"golang.org/x/sync/singleflight"
)

// BundleCache is a simple in-memory cache for CA bundles with request deduplication.
type BundleCache struct {
	mu      sync.RWMutex
	bundles map[string]*cachedBundle
	ttl     time.Duration
	group   singleflight.Group // Deduplicates concurrent requests for the same key
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
// Uses singleflight to deduplicate concurrent requests for the same issuerID.
func (c *BundleCache) Get(ctx context.Context, issuerID string, fetcher types.Fetcher) (*types.CABundle, error) {
	// First check with read lock for cached value
	c.mu.RLock()
	if cached, ok := c.bundles[issuerID]; ok && time.Now().Before(cached.expiresAt) {
		c.mu.RUnlock()
		return cached.bundle, nil
	}
	c.mu.RUnlock()

	// Use singleflight to deduplicate concurrent requests
	v, err, _ := c.group.Do(issuerID, func() (interface{}, error) {
		// Double-check cache inside singleflight (another request might have just populated it)
		c.mu.RLock()
		if cached, ok := c.bundles[issuerID]; ok && time.Now().Before(cached.expiresAt) {
			c.mu.RUnlock()
			return cached.bundle, nil
		}
		c.mu.RUnlock()

		// Fetch the bundle
		bundle, err := fetcher.Fetch(ctx, issuerID)
		if err != nil {
			return nil, err
		}

		// Store in cache
		c.mu.Lock()
		c.bundles[issuerID] = &cachedBundle{
			bundle:    bundle,
			expiresAt: time.Now().Add(c.ttl),
		}
		c.mu.Unlock()

		return bundle, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(*types.CABundle), nil
}
