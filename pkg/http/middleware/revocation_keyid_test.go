package middleware

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/revocation/cabundle"
	"github.com/agentic-research/signet/pkg/revocation/types"
)

type staticFetcher struct{ bundle *types.CABundle }

func (f staticFetcher) Fetch(context.Context, string) (*types.CABundle, error) { return f.bundle, nil }

// signet-676bf1, through the middleware: a token with no key id, checked
// against a bundle that has a keyId but no prevKeyId (the live notme
// shape), must be refused as revoked, not let through.
func TestSignetMiddleware_RevocationChecker_EmptyKeyIDRefused(t *testing.T) {
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &types.CABundle{
		Epoch:    1,
		Seqno:    1,
		Keys:     map[string][]byte{"k1": bundlePub},
		KeyID:    "k1",
		IssuedAt: time.Now().Unix(),
	}
	canonical, err := revocation.BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = ed25519.Sign(bundlePriv, canonical)

	for _, tc := range []struct {
		name     string
		keyID    []byte
		wantCode int
	}{
		{"matching key id is allowed", []byte("k1"), http.StatusOK},
		{"missing key id is refused", nil, http.StatusUnauthorized},
		{"empty key id is refused", []byte{}, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, masterPub, masterPriv := setupTestMiddleware(t)
			record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")
			record.Token.KeyID = tc.keyID // token.Epoch is 1, matching the bundle
			if _, err := config.TokenStore.Store(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			checker := revocation.NewCABundleChecker(staticFetcher{bundle}, cabundle.NewMemoryStorage(), cabundle.NewBundleCache(time.Minute), bundlePub)
			mw, err := SignetMiddleware(
				WithMasterKey(masterPub),
				WithTokenStore(config.TokenStore),
				WithNonceStore(config.NonceStore),
				WithLogger(config.Logger),
				WithRevocationChecker(checker),
			)
			if err != nil {
				t.Fatal(err)
			}
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, createSignedRequest(t, "GET", "/test", record, ephemeralPriv))
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}
