// Demo server using the production middleware package
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"crypto/rand"
	"github.com/jamestexas/signet/pkg/crypto/epr"
	"github.com/jamestexas/signet/pkg/http/middleware"
	"github.com/jamestexas/signet/pkg/signet"
)

var (
	// Server's master key pair
	serverMasterPub, serverMasterPriv, _ = ed25519.GenerateKey(nil)

	// Shared token store for middleware
	tokenStore = middleware.NewMemoryTokenStore()
	nonceStore = middleware.NewMemoryNonceStore()
)

// issueTokenHandler issues tokens that the middleware can verify
func issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Purpose string `json:"purpose"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Purpose == "" {
		req.Purpose = "api-access"
	}

	// Generate ephemeral proof
	generator := epr.NewGenerator(serverMasterPriv)
	proofResp, err := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        req.Purpose,
	})
	if err != nil {
		log.Printf("Failed to generate proof: %v", err)
		http.Error(w, `{"error": "Failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	// Create token
	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralKeyHash := sha256.Sum256(ephemeralPub)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, `{"error": "Failed to generate nonce"}`, http.StatusInternalServerError)
		return
	}

	masterKeyHash := sha256.Sum256(serverMasterPub)
	token := signet.NewToken(
		"demo-server",
		masterKeyHash[:],
		ephemeralKeyHash[:],
		nonce,
		5*time.Minute,
	)

	// Store token for middleware verification
	record := &middleware.TokenRecord{
		Token:              token,
		MasterPublicKey:    serverMasterPub,
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now(),
		Purpose:            req.Purpose,
	}

	tokenID, err := tokenStore.Store(context.Background(), record)
	if err != nil {
		log.Printf("Failed to store token: %v", err)
		http.Error(w, `{"error": "Failed to store token"}`, http.StatusInternalServerError)
		return
	}

	// Marshal token for client
	tokenBytes, err := token.Marshal()
	if err != nil {
		http.Error(w, `{"error": "Failed to marshal token"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token_id":          tokenID,
		"token":             base64.RawURLEncoding.EncodeToString(tokenBytes),
		"ephemeral_public":  base64.RawURLEncoding.EncodeToString(ephemeralPub),
		"ephemeral_private": base64.RawURLEncoding.EncodeToString(proofResp.EphemeralPrivateKey.(ed25519.PrivateKey)),
		"binding_signature": base64.RawURLEncoding.EncodeToString(proofResp.Proof.BindingSignature),
		"master_public":     base64.RawURLEncoding.EncodeToString(serverMasterPub),
		"expires_at":        token.ExpiresAt,
		"purpose":           req.Purpose,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)

	log.Printf("✅ Issued token %s for purpose: %s", tokenID, req.Purpose)
}

// protectedHandler is a handler protected by the middleware
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// The middleware has already verified the request
	// We can access the authentication context
	authCtx, ok := middleware.GetAuthContext(r)
	if !ok {
		http.Error(w, "No authentication context", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Authenticated request from token %s (purpose: %s)", authCtx.TokenID, authCtx.Purpose)

	response := map[string]interface{}{
		"status":   "authenticated",
		"token_id": authCtx.TokenID,
		"purpose":  authCtx.Purpose,
		"issuer":   authCtx.IssuerID,
		"message":  "Successfully authenticated using Signet middleware!",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// adminHandler requires admin-access purpose
func adminHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := middleware.GetAuthContext(r)
	if !ok {
		http.Error(w, "No authentication context", http.StatusInternalServerError)
		return
	}

	// Additional authorization check
	if authCtx.Purpose != "admin-access" {
		http.Error(w, `{"error": "Admin access required"}`, http.StatusForbidden)
		return
	}

	log.Printf("✅ Admin request from token %s", authCtx.TokenID)

	response := map[string]interface{}{
		"status":   "authenticated",
		"token_id": authCtx.TokenID,
		"message":  "Admin access granted!",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	masterHash := sha256.Sum256(serverMasterPub)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "healthy",
		"auth":       "Signet middleware",
		"master_key": hex.EncodeToString(masterHash[:8]),
	})
}

// CustomLogger implements middleware.Logger with colored output
type CustomLogger struct{}

func (l *CustomLogger) Debug(msg string, args ...interface{}) {
	log.Printf("🔍 [DEBUG] %s %v", msg, args)
}

func (l *CustomLogger) Info(msg string, args ...interface{}) {
	log.Printf("ℹ️  [INFO] %s %v", msg, args)
}

func (l *CustomLogger) Warn(msg string, args ...interface{}) {
	log.Printf("⚠️  [WARN] %s %v", msg, args)
}

func (l *CustomLogger) Error(msg string, args ...interface{}) {
	log.Printf("❌ [ERROR] %s %v", msg, args)
}

func main() {
	// Create the Signet middleware with production configuration
	auth := middleware.SignetMiddleware(
		middleware.WithMasterKey(serverMasterPub),
		middleware.WithTokenStore(tokenStore),
		middleware.WithNonceStore(nonceStore),
		middleware.WithClockSkew(30*time.Second),
		middleware.WithJSONErrors(),
		middleware.WithLogger(&CustomLogger{}),
		middleware.WithSkipPaths("/health", "/issue-token"),
	)

	// Setup routes
	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/issue-token", issueTokenHandler)

	// Protected endpoints (auth required)
	mux.Handle("/protected", auth(http.HandlerFunc(protectedHandler)))
	mux.Handle("/admin", auth(http.HandlerFunc(adminHandler)))

	// Apply middleware to all routes
	handler := http.Handler(mux)

	fmt.Println("🔐 Signet Demo Server with Production Middleware")
	fmt.Println("=================================================")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /health       - Health check (no auth)")
	fmt.Println("  POST /issue-token  - Issue a new Signet token")
	fmt.Println("  GET  /protected    - Protected endpoint (requires valid Signet proof)")
	fmt.Println("  GET  /admin        - Admin endpoint (requires admin-access purpose)")
	fmt.Println("")
	fmt.Println("Features:")
	fmt.Println("  ✓ Production-ready middleware package")
	fmt.Println("  ✓ Two-step cryptographic verification")
	fmt.Println("  ✓ Per-request replay prevention")
	fmt.Println("  ✓ Configurable clock skew tolerance")
	fmt.Println("  ✓ JSON error responses")
	fmt.Println("  ✓ Custom logging integration")
	fmt.Println("  ✓ Path-based auth bypass")
	fmt.Println("")
	masterKeyHash := sha256.Sum256(serverMasterPub)
	fmt.Printf("Server Master Key (first 8 bytes): %x\n", masterKeyHash[:8])
	fmt.Println("")
	fmt.Println("Starting server on :8081...")

	log.Fatal(http.ListenAndServe(":8081", handler))
}
