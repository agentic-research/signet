package revocation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/epr"
	"github.com/agentic-research/signet/pkg/http/middleware"
	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/revocation/cabundle"
	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/fxamacker/cbor/v2"
)

func TestRevocation(t *testing.T) {
	// Generate a trust anchor for bundle signing
	bundlePub, bundlePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Set up a test CA bundle server.
	bundle := &types.CABundle{
		Epoch:     2, // The current, valid epoch.
		Seqno:     1,
		Keys:      make(map[string][]byte),
		KeyID:     "",
		PrevKeyID: "",
		IssuedAt:  time.Now().Unix(),
	}

	// Sign the bundle using CBOR
	message := map[int]interface{}{
		1: bundle.Epoch,     // epoch
		2: bundle.Seqno,     // seqno
		3: bundle.Keys,      // keys map
		4: bundle.KeyID,     // current key ID
		5: bundle.PrevKeyID, // previous key ID
		6: bundle.IssuedAt,  // issued timestamp
	}

	encMode, _ := cbor.CanonicalEncOptions().EncMode()
	bundleCanonical, _ := encMode.Marshal(message)
	bundle.Signature = ed25519.Sign(bundlePriv, bundleCanonical)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(bundle); err != nil {
			t.Fatalf("failed to encode bundle: %v", err)
		}
	}))
	defer server.Close()

	// 2. Set up the middleware with a revocation checker.
	config, _, masterPriv := setupTestMiddleware(t)

	fetcher := cabundle.NewHTTPSFetcher(server.URL, nil)
	storage := cabundle.NewMemoryStorage()
	cache := cabundle.NewBundleCache(1 * time.Minute)
	checker := revocation.NewCABundleChecker(fetcher, storage, cache, bundlePub)

	mw, err := middleware.SignetMiddleware(
		middleware.WithTokenStore(config.TokenStore),
		middleware.WithNonceStore(config.NonceStore),
		middleware.WithKeyProvider(config.KeyProvider),
		middleware.WithRevocationChecker(checker),
	)
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	// 3. Generate a token with a revoked epoch.
	record, ephemeralPriv := generateTestToken(t, masterPriv, "test-purpose")
	record.Token.Epoch = 1 // This epoch is revoked.

	// 4. Store the token in the middleware's token store.
	_, err = config.TokenStore.Store(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Create a signed request with the revoked token.
	req := createSignedRequest(t, "GET", "/test", record, ephemeralPriv)

	// 6. Serve the request and check the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	mw(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status code %d, got %d", http.StatusUnauthorized, rr.Code)
	}

	// The default error handler uses the simple error text
	expectedBody := "token revoked\n"
	if rr.Body.String() != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, rr.Body.String())
	}
}

// setupTestMiddleware creates a middleware instance with test configuration
func setupTestMiddleware(t *testing.T) (*middleware.Config, ed25519.PublicKey, ed25519.PrivateKey) {
	masterPub, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	config := &middleware.Config{
		ClockSkew:      30 * time.Second,
		TokenStore:     middleware.NewMemoryTokenStore(),
		NonceStore:     middleware.NewMemoryNonceStore(),
		ErrorHandler:   middleware.DefaultErrorHandler,
		RequestBuilder: middleware.DefaultRequestBuilder,
		Logger:         &testLogger{t: t},
		Metrics:        &middleware.NoOpMetrics{},
	}

	// Use WithMasterKey option to set the key provider
	opt := middleware.WithMasterKey(masterPub)
	opt(config)

	return config, masterPub, masterPriv
}

// testLogger implements Logger for testing
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] %s: %v", msg, args)
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] %s: %v", msg, args)
}

func (l *testLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] %s: %v", msg, args)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] %s: %v", msg, args)
}

// generateTestToken creates a valid token with ephemeral binding
func generateTestToken(t *testing.T, masterPriv ed25519.PrivateKey, purpose string) (*middleware.TokenRecord, ed25519.PrivateKey) {
	// Generate ephemeral proof
	generator := epr.NewGenerator(masterPriv)
	proofResp, err := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        purpose,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create token
	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralPriv := proofResp.EphemeralPrivateKey.Key()
	if ephemeralPriv == nil {
		t.Fatal("ephemeralPriv is nil")
	}

	// Verify key consistency
	derivedPub := ephemeralPriv.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, ephemeralPub) {
		t.Fatal("public keys don't match")
	}

	ephemeralKeyHash := sha256.Sum256(ephemeralPub)
	masterKeyHash := sha256.Sum256(masterPriv.Public().(ed25519.PublicKey))

	nonce := []byte("test-nonce-12345")
	token, err := signet.NewToken(
		"test-issuer",
		masterKeyHash[:],
		ephemeralKeyHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	token.Epoch = 1

	record := &middleware.TokenRecord{
		Token:              token,
		MasterPublicKey:    masterPriv.Public().(ed25519.PublicKey),
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now(),
		Purpose:            purpose,
	}

	return record, ephemeralPriv
}

// createSignedRequest creates a request with a valid Signet-Proof header
func createSignedRequest(t *testing.T, method, path string, record *middleware.TokenRecord, ephemeralPriv ed25519.PrivateKey) *http.Request {
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16) // Must be exactly 16 bytes
	copy(nonce, []byte("request-nonce123"))

	// Create canonical request
	canonical := fmt.Sprintf("%s|%s|%d|%s",
		method,
		path,
		timestamp,
		base64.RawURLEncoding.EncodeToString(nonce),
	)

	// Sign with ephemeral key
	signature := ed25519.Sign(ephemeralPriv, []byte(canonical))

	// Build proof header
	proofHeader := fmt.Sprintf("v1;m=compact;jti=%s;cap=%s;s=%s;n=%s;ts=%d",
		base64.RawURLEncoding.EncodeToString(record.Token.JTI),
		base64.RawURLEncoding.EncodeToString(record.Token.CapabilityID),
		base64.RawURLEncoding.EncodeToString(signature),
		base64.RawURLEncoding.EncodeToString(nonce),
		timestamp,
	)

	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Signet-Proof", proofHeader)

	return req
}
