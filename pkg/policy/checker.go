package policy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/agentic-research/signet/pkg/revocation/types"
	"golang.org/x/sync/singleflight"
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
// Uses singleflight to deduplicate concurrent fetch requests (same pattern
// as cabundle.BundleCache).
type PolicyChecker struct {
	fetcher     BundleFetcher
	storage     types.Storage // persists lastSeqno across restarts (reuses revocation.types)
	trustAnchor ed25519.PublicKey
	cacheTTL    time.Duration
	logger      *slog.Logger

	mu          sync.RWMutex
	cached      *TrustPolicyBundle
	cachedAt    time.Time
	bootstrapOK bool // true until first bundle is observed
	group       singleflight.Group
}

// PolicyCheckerOption configures a PolicyChecker.
type PolicyCheckerOption func(*PolicyChecker)

// WithStorage sets persistent seqno storage (reuses types.Storage from pkg/revocation).
// Without this, seqno resets to 0 on restart — rollback protection is weakened.
func WithStorage(s types.Storage) PolicyCheckerOption {
	return func(c *PolicyChecker) { c.storage = s }
}

// WithLogger sets a structured logger for the checker.
func WithLogger(l *slog.Logger) PolicyCheckerOption {
	return func(c *PolicyChecker) { c.logger = l }
}

// NewPolicyChecker creates a new PolicyChecker.
// Starts in bootstrap mode: if no bundle has been fetched, all subjects are allowed.
// Once the first bundle is observed, bootstrap mode is permanently disabled.
func NewPolicyChecker(fetcher BundleFetcher, trustAnchor ed25519.PublicKey, cacheTTL time.Duration, opts ...PolicyCheckerOption) *PolicyChecker {
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}
	c := &PolicyChecker{
		fetcher:     fetcher,
		trustAnchor: trustAnchor,
		cacheTTL:    cacheTTL,
		bootstrapOK: true,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.storage == nil {
		c.logger.Warn("PolicyChecker: no persistent storage configured — seqno rollback protection resets on restart")
	}
	return c
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
//
// Uses singleflight to deduplicate concurrent fetch requests, fixing the TOCTOU
// race where multiple goroutines could read bootstrapOK=true between the first
// bundle install and their own fetch completion.
func (c *PolicyChecker) getBundle(ctx context.Context) (*TrustPolicyBundle, bool, error) {
	c.mu.RLock()
	if c.cached != nil && time.Since(c.cachedAt) < c.cacheTTL {
		bundleAge := time.Since(time.Unix(int64(c.cached.IssuedAt), 0))
		if bundleAge <= maxPolicyBundleAge {
			bundle := c.cached
			c.mu.RUnlock()
			return bundle, false, nil
		}
	}
	c.mu.RUnlock()

	// Singleflight deduplicates concurrent fetches (same pattern as cabundle.BundleCache)
	v, err, _ := c.group.Do("policy-bundle", func() (any, error) {
		// Double-check cache inside singleflight
		c.mu.RLock()
		if c.cached != nil && time.Since(c.cachedAt) < c.cacheTTL {
			bundleAge := time.Since(time.Unix(int64(c.cached.IssuedAt), 0))
			if bundleAge <= maxPolicyBundleAge {
				bundle := c.cached
				c.mu.RUnlock()
				return bundle, nil
			}
		}
		c.mu.RUnlock()

		bundle, err := c.fetcher.Fetch(ctx)
		if err != nil {
			return nil, err
		}

		// Verify signature
		if err := bundle.Verify(c.trustAnchor); err != nil {
			return nil, fmt.Errorf("bundle signature invalid: %w", err)
		}

		// Check bundle age
		bundleAge := time.Since(time.Unix(int64(bundle.IssuedAt), 0))
		if bundleAge > maxPolicyBundleAge {
			return nil, fmt.Errorf("bundle too stale: %v old (max %v)", bundleAge, maxPolicyBundleAge)
		}

		// Monotonic seqno check — use persistent storage if available
		lastSeqno, err := c.getLastSeqno(ctx)
		if err != nil {
			return nil, fmt.Errorf("get last seqno: %w", err)
		}
		if bundle.Seqno < lastSeqno {
			return nil, fmt.Errorf("bundle seqno %d < last seen %d (rollback attack?)", bundle.Seqno, lastSeqno)
		}

		// Persist seqno before installing bundle
		if err := c.setSeqno(ctx, bundle.Seqno); err != nil {
			return nil, fmt.Errorf("persist seqno: %w", err)
		}

		// Install bundle and permanently disable bootstrap (under write lock)
		c.mu.Lock()
		c.bootstrapOK = false
		c.cached = bundle
		c.cachedAt = time.Now()
		c.mu.Unlock()

		return bundle, nil
	})

	if err != nil {
		// Check bootstrap AFTER singleflight completes — this is now race-free
		// because bootstrap is only read here, and only written inside singleflight
		c.mu.RLock()
		bootstrap := c.bootstrapOK
		c.mu.RUnlock()
		return nil, bootstrap, fmt.Errorf("fetch policy bundle: %w", err)
	}

	return v.(*TrustPolicyBundle), false, nil
}

// getLastSeqno reads from persistent storage if configured, else returns 0.
func (c *PolicyChecker) getLastSeqno(ctx context.Context) (uint64, error) {
	if c.storage == nil {
		return 0, nil
	}
	return c.storage.GetLastSeenSeqno(ctx, "policy-bundle")
}

// setSeqno persists to storage if configured.
func (c *PolicyChecker) setSeqno(ctx context.Context, seqno uint64) error {
	if c.storage == nil {
		return nil
	}
	return c.storage.SetLastSeenSeqnoIfGreater(ctx, "policy-bundle", seqno)
}
