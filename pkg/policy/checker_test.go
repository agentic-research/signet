package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// mockFetcher implements BundleFetcher for testing.
type mockFetcher struct {
	bundle *TrustPolicyBundle
	err    error
}

func (m *mockFetcher) Fetch(_ context.Context) (*TrustPolicyBundle, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.bundle, nil
}

func newSignedBundle(t *testing.T, priv ed25519.PrivateKey, seqno uint64, subjects map[string]*Subject, groups map[string]*Group) *TrustPolicyBundle {
	t.Helper()
	b := &TrustPolicyBundle{
		Epoch:    1,
		Seqno:    seqno,
		IssuedAt: uint64(time.Now().Unix()),
		Subjects: subjects,
		Groups:   groups,
	}
	if err := b.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPolicyChecker_BootstrapMode(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fetcher := &mockFetcher{err: fmt.Errorf("no bundle server")}
	checker := NewPolicyChecker(fetcher, pub, time.Second)

	if !checker.IsBootstrap() {
		t.Fatal("expected bootstrap mode on init")
	}

	// In bootstrap mode, even with fetch failure, subject is allowed
	subject, err := checker.CheckSubject(context.Background(), "anyone")
	if err != nil {
		t.Fatalf("bootstrap mode should allow: %v", err)
	}
	if !subject.Active {
		t.Error("bootstrap subject should be active")
	}
}

func TestPolicyChecker_CheckSubject_Active(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"github-123": {Active: true, Groups: []string{"dev"}}},
		map[string]*Group{"dev": {CapTokens: []uint64{1}}},
	)
	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, time.Second)

	subject, err := checker.CheckSubject(context.Background(), "github-123")
	if err != nil {
		t.Fatalf("expected allowed: %v", err)
	}
	if !subject.Active {
		t.Error("expected active")
	}

	// Bootstrap mode should be disabled after first successful fetch
	if checker.IsBootstrap() {
		t.Error("bootstrap should be disabled after first bundle")
	}
}

func TestPolicyChecker_CheckSubject_NotProvisioned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"github-123": {Active: true}},
		map[string]*Group{},
	)
	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, time.Second)

	_, err := checker.CheckSubject(context.Background(), "unknown-user")
	if err == nil {
		t.Fatal("expected error for unprovisioned subject")
	}
}

func TestPolicyChecker_CheckSubject_Deactivated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"fired-employee": {Active: false}},
		map[string]*Group{},
	)
	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, time.Second)

	_, err := checker.CheckSubject(context.Background(), "fired-employee")
	if err == nil {
		t.Fatal("expected error for deactivated subject")
	}
}

func TestPolicyChecker_RollbackProtection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	subjects := map[string]*Subject{"user": {Active: true}}
	groups := map[string]*Group{}

	bundle1 := newSignedBundle(t, priv, 10, subjects, groups)
	bundle2 := newSignedBundle(t, priv, 5, subjects, groups) // lower seqno

	fetcher := &mockFetcher{bundle: bundle1}
	checker := NewPolicyChecker(fetcher, pub, 0) // no cache

	// First fetch succeeds
	_, err := checker.CheckSubject(context.Background(), "user")
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	// Serve a bundle with lower seqno (rollback)
	fetcher.bundle = bundle2
	checker.cachedAt = time.Time{} // force re-fetch

	_, err = checker.CheckSubject(context.Background(), "user")
	if err == nil {
		t.Fatal("expected rollback detection")
	}
}

func TestPolicyChecker_RejectsStaleBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := &TrustPolicyBundle{
		Epoch:    1,
		Seqno:    1,
		IssuedAt: uint64(time.Now().Add(-2 * time.Hour).Unix()), // 2 hours old
		Subjects: map[string]*Subject{"user": {Active: true}},
		Groups:   map[string]*Group{},
	}
	_ = bundle.Sign(priv)

	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, 0)

	_, err := checker.CheckSubject(context.Background(), "user")
	if err == nil {
		t.Fatal("expected stale bundle rejection")
	}
}

func TestPolicyChecker_RejectsInvalidSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"user": {Active: true}},
		map[string]*Group{},
	)

	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, otherPub, 0) // wrong trust anchor

	_, err := checker.CheckSubject(context.Background(), "user")
	if err == nil {
		t.Fatal("expected signature rejection")
	}
}

func TestPolicyChecker_CacheTTL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"user": {Active: true}},
		map[string]*Group{},
	)

	fetcher := &mockFetcher{bundle: bundle}

	checker := NewPolicyChecker(fetcher, pub, 5*time.Second)

	// First call fetches
	_, _ = checker.CheckSubject(context.Background(), "user")

	// Second call within TTL should use cache (no re-fetch)
	// We verify by making fetcher return error — cached result should still work
	fetcher.err = fmt.Errorf("server down")
	subject, err := checker.CheckSubject(context.Background(), "user")
	if err != nil {
		t.Fatalf("expected cache hit: %v", err)
	}
	if !subject.Active {
		t.Error("cached subject should be active")
	}
}

func TestPolicyChecker_BootstrapDisabledPermanently(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := newSignedBundle(t, priv, 1,
		map[string]*Subject{"user": {Active: true}},
		map[string]*Group{},
	)

	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, 0)

	// First fetch — disables bootstrap
	_, _ = checker.CheckSubject(context.Background(), "user")

	// Now make fetcher fail
	fetcher.err = fmt.Errorf("down")
	checker.cachedAt = time.Time{} // force re-fetch

	// Should NOT fall back to bootstrap — fail closed
	_, err := checker.CheckSubject(context.Background(), "unknown")
	if err == nil {
		t.Fatal("expected fail-closed after bootstrap disabled")
	}
}
