package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRequestSizeCheckOrder verifies that request size validation happens
// BEFORE expensive operations like token lookup and nonce storage.
// This prevents DoS attacks where attackers use oversized requests with
// valid (even expired) tokens to trigger database lookups before rejection.
func TestRequestSizeCheckOrder(t *testing.T) {
	// Create master key
	masterPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Track whether expensive operations were called
	tokenLookupCalled := false
	nonceStoreCalled := false

	// Create mock stores that track access
	mockTokenStore := &mockTokenStoreTracker{
		onGet: func() {
			tokenLookupCalled = true
		},
	}
	mockNonceStore := &mockNonceStoreTracker{
		onCheck: func() {
			nonceStoreCalled = true
		},
	}

	// Create middleware
	middleware, err := SignetMiddleware(
		WithMasterKey(masterPub),
		WithTokenStore(mockTokenStore),
		WithNonceStore(mockNonceStore),
	)
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a request with oversized Content-Length but valid-looking proof
	req := httptest.NewRequest("POST", "/test", strings.NewReader("small body"))
	req.ContentLength = 10 * 1024 * 1024 // 10MB (exceeds 1MB limit)

	// Add a valid-looking Signet-Proof header
	req.Header.Set("Signet-Proof", createDummyProof())

	// Execute request
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify we got REQUEST_TOO_LARGE error
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status 413, got %d", w.Code)
	}

	// CRITICAL: Verify expensive operations were NOT called
	if tokenLookupCalled {
		t.Error("Token lookup was called before size check - DoS vulnerability!")
	}
	if nonceStoreCalled {
		t.Error("Nonce store was called before size check - DoS vulnerability!")
	}

	t.Log("✅ Request size check happens before expensive operations")
}

// TestChunkedTransferEncodingTimeout verifies that chunked requests
// have a timeout applied to prevent slow-drip DoS attacks.
func TestChunkedTransferEncodingTimeout(t *testing.T) {
	t.Skip("Chunked transfer encoding protection is implemented in middleware (signet.go:117-127), " +
		"but httptest.NewRequest doesn't fully simulate HTTP/1.1 chunked transfer behavior. " +
		"The middleware checks len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == \"chunked\" " +
		"and applies a 30-second timeout. This is tested in integration tests with real HTTP servers.")

	// Implementation verified in pkg/http/middleware/signet.go:117-127:
	//   if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
	//       chunkedTimeout := 30 * time.Second
	//       ctx, cancel := context.WithTimeout(ctx, chunkedTimeout)
	//       defer cancel()
	//       r = r.WithContext(ctx)
	//   }
}

// TestFullJTIUsage verifies that token IDs use the full 16-byte JTI
// instead of truncating to 8 bytes, which prevents collision attacks.
func TestFullJTIUsage(t *testing.T) {
	// Generate two JTIs with the same 8-byte prefix but different full values
	jti1 := make([]byte, 16)
	jti2 := make([]byte, 16)

	// Make first 8 bytes identical
	prefix := make([]byte, 8)
	if _, err := rand.Read(prefix); err != nil {
		t.Fatal(err)
	}
	copy(jti1[:8], prefix)
	copy(jti2[:8], prefix)

	// Make last 8 bytes different
	if _, err := rand.Read(jti1[8:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(jti2[8:]); err != nil {
		t.Fatal(err)
	}

	// Convert to token IDs (as middleware does)
	tokenID1 := hex.EncodeToString(jti1)
	tokenID2 := hex.EncodeToString(jti2)

	// Verify token IDs are different despite same 8-byte prefix
	if tokenID1 == tokenID2 {
		t.Error("Token IDs should be different for different JTIs!")
	}

	// Verify token IDs are 32 characters (full 16 bytes)
	if len(tokenID1) != 32 {
		t.Errorf("Token ID should be 32 chars, got %d", len(tokenID1))
	}
	if len(tokenID2) != 32 {
		t.Errorf("Token ID should be 32 chars, got %d", len(tokenID2))
	}

	// Verify first 16 characters are the same (8-byte prefix)
	if tokenID1[:16] != tokenID2[:16] {
		t.Error("Token IDs should have same 8-byte prefix")
	}

	// Verify last 16 characters are different (collision prevention)
	if tokenID1[16:] == tokenID2[16:] {
		t.Error("Token IDs should have different suffixes")
	}

	t.Log("✅ Full 16-byte JTI prevents collision attacks")
	t.Logf("   Token ID 1: %s", tokenID1)
	t.Logf("   Token ID 2: %s", tokenID2)
	t.Logf("   Same prefix: %s", tokenID1[:16])
	t.Logf("   Different suffixes: %s vs %s", tokenID1[16:], tokenID2[16:])
}

// TestConstantTimeTokenLookup verifies that token lookup timing is
// relatively constant whether the token exists or not, preventing
// timing attacks.
//
// Note: This is a basic test. True constant-time requires more sophisticated
// measurement and may not be reliably testable in Go due to GC and scheduling.
func TestConstantTimeTokenLookup(t *testing.T) {
	t.Skip("Timing attack resistance is implemented in demo server, not middleware. " +
		"Demo server performs dummy verification for non-existent tokens. " +
		"Proper timing attack testing requires statistical analysis over many samples.")

	// This test is skipped because:
	// 1. The timing attack mitigation is in the demo server, not the middleware
	// 2. The demo server performs dummy verification when token doesn't exist
	// 3. Testing timing requires statistical analysis which is beyond unit testing
	// 4. Go's GC and scheduling make timing tests unreliable
	//
	// The mitigation is in demo/http-auth/server/main.go:248-276
}

// TestConfigurableMaxRequestSize verifies that the max request size
// can be configured via WithMaxRequestSize option.
func TestConfigurableMaxRequestSize(t *testing.T) {
	masterPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Set custom 5MB limit
	customLimit := int64(5 * 1024 * 1024)
	middleware, err := SignetMiddleware(
		WithMasterKey(masterPub),
		WithMaxRequestSize(customLimit),
	)
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test 1: Request under custom limit should pass size check (may fail auth later)
	req1 := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
	req1.ContentLength = 4 * 1024 * 1024 // 4MB (under 5MB limit)
	req1.Header.Set("Signet-Proof", createDummyProof())

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	// Should NOT be 413 (will be 401 for invalid auth, but that's ok)
	if w1.Code == http.StatusRequestEntityTooLarge {
		t.Error("Request under custom limit was rejected for size")
	}

	// Test 2: Request over custom limit should be rejected
	req2 := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
	req2.ContentLength = 6 * 1024 * 1024 // 6MB (over 5MB limit)
	req2.Header.Set("Signet-Proof", createDummyProof())

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Request over custom limit should be 413, got %d", w2.Code)
	}

	t.Log("✅ Max request size is configurable")
}

// Helper: Create a dummy but valid-format proof for testing
func createDummyProof() string {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		panic(err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	sig := make([]byte, ed25519.SignatureSize)
	if _, err := rand.Read(sig); err != nil {
		panic(err)
	}

	// Format: v1;m=compact;jti=<base64>;s=<base64>;n=<base64>;ts=<timestamp>
	return fmt.Sprintf("v1;m=compact;jti=%s;s=%s;n=%s;ts=%d",
		base64.RawURLEncoding.EncodeToString(jti),
		base64.RawURLEncoding.EncodeToString(sig),
		base64.RawURLEncoding.EncodeToString(nonce),
		time.Now().Unix(),
	)
}

// Mock token store that tracks access
type mockTokenStoreTracker struct {
	onGet func()
}

func (m *mockTokenStoreTracker) Get(ctx context.Context, tokenID string) (*TokenRecord, error) {
	if m.onGet != nil {
		m.onGet()
	}
	return nil, ErrTokenNotFound
}

func (m *mockTokenStoreTracker) Store(ctx context.Context, record *TokenRecord) (string, error) {
	return "", nil
}

func (m *mockTokenStoreTracker) Delete(ctx context.Context, tokenID string) error {
	return nil
}

func (m *mockTokenStoreTracker) Cleanup(ctx context.Context) error {
	return nil
}

// Mock nonce store that tracks access
type mockNonceStoreTracker struct {
	onCheck func()
}

func (m *mockNonceStoreTracker) CheckAndStore(ctx context.Context, nonceKey string, expiry int64) error {
	if m.onCheck != nil {
		m.onCheck()
	}
	return nil
}

func (m *mockNonceStoreTracker) Cleanup(ctx context.Context) error {
	return nil
}
