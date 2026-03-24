package policy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"
)

const (
	// maxPolicyBundleAge is the maximum allowed age for a policy bundle.
	// Matches CA bundle maxBundleAge (ADR-006 consistency).
	maxPolicyBundleAge = 1 * time.Hour
)

// BundleFetcher retrieves the current trust policy bundle.
type BundleFetcher interface {
	Fetch(ctx context.Context) (*TrustPolicyBundle, error)
}

// PolicyChecker verifies subjects against the current trust policy bundle.
// Parallel to CABundleChecker (pkg/revocation/checker.go).
//
// The checker caches the bundle with a configurable TTL and verifies
// signature, seqno monotonicity, and bundle age on each fetch.
type PolicyChecker struct {
	fetcher     BundleFetcher
	trustAnchor ed25519.PublicKey
	cacheTTL    time.Duration

	mu          sync.RWMutex
	cached      *TrustPolicyBundle
	cachedAt    time.Time
	lastSeqno   uint64
	bootstrapOK bool // true until first bundle is observed
}

// NewPolicyChecker creates a new PolicyChecker.
// Starts in bootstrap mode: if no bundle has been fetched, all subjects are allowed.
// Once the first bundle is observed, bootstrap mode is permanently disabled.
func NewPolicyChecker(fetcher BundleFetcher, trustAnchor ed25519.PublicKey, cacheTTL time.Duration) *PolicyChecker {
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}
	return &PolicyChecker{
		fetcher:     fetcher,
		trustAnchor: trustAnchor,
		cacheTTL:    cacheTTL,
		bootstrapOK: true,
	}
}

// CheckSubject verifies a subject is provisioned and active.
// Returns the Subject policy (for capability resolution) or an error.
//
// In bootstrap mode (no bundle ever fetched), returns a synthetic
// "allow all" subject. Once the first bundle arrives, bootstrap mode
// is permanently disabled and all lookups go through the bundle.
func (c *PolicyChecker) CheckSubject(ctx context.Context, subjectID string) (*Subject, error) {
	bundle, bootstrapFallback, err := c.getBundle(ctx)
	if err != nil {
		if bootstrapFallback {
			return &Subject{Active: true}, nil
		}
		return nil, fmt.Errorf("policy check failed: %w", err)
	}

	subject := bundle.LookupSubject(subjectID)
	if subject == nil {
		return nil, fmt.Errorf("subject %q not provisioned", subjectID)
	}
	if !subject.Active {
		return nil, fmt.Errorf("subject %q is deactivated", subjectID)
	}

	return subject, nil
}

// ResolveCapabilities returns the capability set for a subject.
// In bootstrap mode with a fetch failure, returns nil capabilities (allow-all
// with no specific grants) to align with CheckSubject's bootstrap behavior.
func (c *PolicyChecker) ResolveCapabilities(ctx context.Context, subject *Subject) ([]uint64, error) {
	bundle, bootstrapFallback, err := c.getBundle(ctx)
	if err != nil {
		if bootstrapFallback {
			return nil, nil
		}
		return nil, err
	}
	return bundle.ResolveCapabilities(subject), nil
}

// IsBootstrap returns true if no policy bundle has been observed yet.
func (c *PolicyChecker) IsBootstrap() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bootstrapOK
}

// getBundle returns the cached bundle or fetches a fresh one.
// The second return value indicates whether bootstrap fallback is appropriate:
// true only when the fetcher itself fails (network error), NOT when validation
// (signature, staleness, rollback) fails.
func (c *PolicyChecker) getBundle(ctx context.Context) (*TrustPolicyBundle, bool, error) {
	c.mu.RLock()
	if c.cached != nil && time.Since(c.cachedAt) < c.cacheTTL {
		// Also check bundle age on cache hit to enforce freshness
		bundleAge := time.Since(time.Unix(int64(c.cached.IssuedAt), 0))
		if bundleAge <= maxPolicyBundleAge {
			bundle := c.cached
			c.mu.RUnlock()
			return bundle, false, nil
		}
	}
	bootstrap := c.bootstrapOK
	c.mu.RUnlock()

	// Cache miss — fetch fresh bundle
	bundle, err := c.fetcher.Fetch(ctx)
	if err != nil {
		// Fetch failure (network) — bootstrap fallback eligible
		return nil, bootstrap, fmt.Errorf("fetch policy bundle: %w", err)
	}

	// From here, we have a bundle — validation failures are NOT bootstrap-eligible
	// (a tampered/stale bundle is worse than no bundle)

	// Verify signature
	if err := bundle.Verify(c.trustAnchor); err != nil {
		return nil, false, fmt.Errorf("bundle signature invalid: %w", err)
	}

	// Check bundle age
	bundleAge := time.Since(time.Unix(int64(bundle.IssuedAt), 0))
	if bundleAge > maxPolicyBundleAge {
		return nil, false, fmt.Errorf("bundle too stale: %v old (max %v)", bundleAge, maxPolicyBundleAge)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Monotonic seqno check
	if bundle.Seqno < c.lastSeqno {
		return nil, false, fmt.Errorf("bundle seqno %d < last seen %d (rollback attack?)", bundle.Seqno, c.lastSeqno)
	}

	// Permanently disable bootstrap mode
	c.bootstrapOK = false
	c.cached = bundle
	c.cachedAt = time.Now()
	c.lastSeqno = bundle.Seqno

	return bundle, false, nil
}
