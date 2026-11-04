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
	"github.com/agentic-research/signet/pkg/signet"
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

// signedBundle returns a CA bundle for keys, signed by a fresh bundle key,
// and that key's public half (the checker's trust anchor).
func signedBundle(t *testing.T, keys map[string][]byte, keyID, prevKeyID string) (*types.CABundle, ed25519.PublicKey) {
	t.Helper()
	anchorPub, anchorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &types.CABundle{
		Epoch:     1,
		Seqno:     1,
		Keys:      keys,
		KeyID:     keyID,
		PrevKeyID: prevKeyID,
		IssuedAt:  time.Now().Unix(),
	}
	canonical, err := revocation.BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = ed25519.Sign(anchorPriv, canonical)
	return bundle, anchorPub
}

// signet-708f30: a token from signet's own issuer (signet.NewToken
// WithIssuerKey, via generateTestToken) is accepted by SignetMiddleware with
// a real CABundleChecker while the bundle lists the issuing key as current
// or previous, and refused as revoked once the key has rotated out.
func TestSignetMiddleware_RevocationChecker_IssuedTokenEndToEnd(t *testing.T) {
	retired1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	retired2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherKID1, err := signet.IssuerKeyID(retired1)
	if err != nil {
		t.Fatal(err)
	}
	otherKID2, err := signet.IssuerKeyID(retired2)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		bundle   func(issuerKID string, issuerPub ed25519.PublicKey) (keys map[string][]byte, keyID, prevKeyID string)
		wantCode int
	}{
		{
			name: "issuing key is the bundle's current key",
			bundle: func(kid string, pub ed25519.PublicKey) (map[string][]byte, string, string) {
				return map[string][]byte{kid: pub}, kid, ""
			},
			wantCode: http.StatusOK,
		},
		{
			name: "issuing key is the bundle's previous key (rotation grace)",
			bundle: func(kid string, pub ed25519.PublicKey) (map[string][]byte, string, string) {
				return map[string][]byte{otherKID1: retired1, kid: pub}, otherKID1, kid
			},
			wantCode: http.StatusOK,
		},
		{
			name: "rotated out: neither current nor previous",
			bundle: func(string, ed25519.PublicKey) (map[string][]byte, string, string) {
				return map[string][]byte{otherKID1: retired1, otherKID2: retired2}, otherKID2, otherKID1
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "rotated out: a new current key and no previous",
			bundle: func(string, ed25519.PublicKey) (map[string][]byte, string, string) {
				return map[string][]byte{otherKID1: retired1}, otherKID1, ""
			},
			wantCode: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, masterPub, masterPriv := setupTestMiddleware(t)
			record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")

			issuerKID, err := signet.IssuerKeyID(masterPub)
			if err != nil {
				t.Fatal(err)
			}
			// The rotated-out cases mean something only for a token that
			// names its issuing key; without one it is refused vacuously.
			if string(record.Token.KeyID) != issuerKID {
				t.Fatalf("issued token key id %q, want the issuing key's %q", record.Token.KeyID, issuerKID)
			}
			keys, keyID, prevKeyID := tc.bundle(issuerKID, masterPub)
			bundle, anchor := signedBundle(t, keys, keyID, prevKeyID)

			if _, err := config.TokenStore.Store(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			checker := revocation.NewCABundleChecker(staticFetcher{bundle}, cabundle.NewMemoryStorage(), cabundle.NewBundleCache(time.Minute), anchor)
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
				t.Fatalf("status %d, want %d (token key id %q, bundle keyId %q prevKeyId %q): %s",
					rec.Code, tc.wantCode, record.Token.KeyID, keyID, prevKeyID, rec.Body.String())
			}
		})
	}
}
