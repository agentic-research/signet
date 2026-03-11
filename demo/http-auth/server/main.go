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
	"os"
	"sync"
	"time"

	"crypto/rand"

	"github.com/agentic-research/signet/pkg/crypto/cose"
	"github.com/agentic-research/signet/pkg/crypto/epr"
	"github.com/agentic-research/signet/pkg/http/header"
	"github.com/agentic-research/signet/pkg/signet"
)

// TokenRegistry stores issued tokens for verification
// In production, this would be a distributed cache or database
//
// Performance Note: Uses sync.Map for lock-free reads under high concurrency.
// This eliminates lock contention that occurs with mutex-protected maps,
// especially beneficial for read-heavy workloads (typical in auth systems).
type TokenRegistry struct {
	tokens sync.Map // token_id (string) -> *TokenRecord (lock-free concurrent access)
}

type TokenRecord struct {
	Token              *signet.Token
	MasterPublicKey    ed25519.PublicKey
	EphemeralPublicKey ed25519.PublicKey
	BindingSignature   []byte
	IssuedAt           time.Time
	Purpose            string
}

func NewTokenRegistry() *TokenRegistry {
	tr := &TokenRegistry{}
	// Clean up expired tokens periodically
	go tr.cleanup()
	return tr
}

func (tr *TokenRegistry) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		// Range over sync.Map (safe for concurrent access)
		tr.tokens.Range(func(key, value interface{}) bool {
			id := key.(string)
			record := value.(*TokenRecord)
			// Remove tokens expired for more than 5 minutes
			if record.Token.IsExpired() && now.Sub(time.Unix(record.Token.ExpiresAt, 0)) > 5*time.Minute {
				tr.tokens.Delete(id)
				log.Printf("Cleaned up expired token: %s", id[:8])
			}
			return true // continue iteration
		})
	}
}

func (tr *TokenRegistry) Store(record *TokenRecord) string {
	// FIX: Use JTI for the map key, because that is what the client sends in the proof header.
	// The protectedHandler extracts tokenID from proof.JTI, so we must store by JTI.
	tokenID := hex.EncodeToString(record.Token.JTI)
	// sync.Map.Store is atomic and lock-free
	tr.tokens.Store(tokenID, record)
	return tokenID
}

func (tr *TokenRegistry) Get(tokenID string) (*TokenRecord, bool) {
	// sync.Map.Load is lock-free (no contention on reads)
	if val, ok := tr.tokens.Load(tokenID); ok {
		return val.(*TokenRecord), true
	}
	return nil, false
}

// NonceTracker prevents replay attacks
type NonceTracker struct {
	mu   sync.RWMutex
	seen map[string]map[int64]bool // token_id -> timestamp -> seen
}

func NewNonceTracker() *NonceTracker {
	return &NonceTracker{
		seen: make(map[string]map[int64]bool),
	}
}

func (nt *NonceTracker) CheckAndStore(tokenID string, timestamp int64) error {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	if nt.seen[tokenID] == nil {
		nt.seen[tokenID] = make(map[int64]bool)
	}

	if nt.seen[tokenID][timestamp] {
		return fmt.Errorf("replay detected: timestamp already used for this token")
	}

	nt.seen[tokenID][timestamp] = true
	return nil
}

var (
	// Server's master key pair (in production, this would be in HSM/secure storage)
	serverMasterPub, serverMasterPriv, _ = ed25519.GenerateKey(nil)
	tokenRegistry                        = NewTokenRegistry()
	nonceTracker                         = NewNonceTracker()
)

// issueTokenHandler issues a new Signet token with proper two-step binding
func issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Purpose string `json:"purpose"` // e.g., "http-api-access"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Purpose == "" {
		req.Purpose = "http-api-access"
	}

	// Generate ephemeral proof using the EPR generator
	generator := epr.NewGenerator(serverMasterPriv)
	proofResp, err := generator.GenerateProof(context.Background(), &epr.ProofRequest{
		ValidityPeriod: 5 * time.Minute,
		Purpose:        req.Purpose,
	})
	// CRITICAL: Zeroize ephemeral key immediately, even if error occurs
	// This prevents key leakage if GenerateProof partially succeeds or
	// if any subsequent operation fails before the handler completes.
	if proofResp != nil && proofResp.EphemeralPrivateKey != nil {
		defer proofResp.EphemeralPrivateKey.Destroy()
	}
	if err != nil {
		log.Printf("Failed to generate proof: %v", err)
		http.Error(w, `{"error": "Failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	// Create token with ephemeral key binding
	ephemeralPub := proofResp.Proof.EphemeralPublicKey.(ed25519.PublicKey)
	ephemeralKeyHash := sha256.Sum256(ephemeralPub)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, `{"error": "Failed to generate nonce"}`, http.StatusInternalServerError)
		return
	}

	masterKeyHash := sha256.Sum256(serverMasterPub)
	token, err := signet.NewToken(
		"demo-server",
		masterKeyHash[:],
		ephemeralKeyHash[:],
		nonce,
		5*time.Minute,
	)
	if err != nil {
		log.Printf("failed to construct token: %v", err)
		http.Error(w, `{"error": "Failed to build token"}`, http.StatusInternalServerError)
		return
	}

	// Store token record with full cryptographic context
	record := &TokenRecord{
		Token:              token,
		MasterPublicKey:    serverMasterPub,
		EphemeralPublicKey: ephemeralPub,
		BindingSignature:   proofResp.Proof.BindingSignature,
		IssuedAt:           time.Now(),
		Purpose:            req.Purpose,
	}
	tokenID := tokenRegistry.Store(record)

	// Create SIG1 wire format using the ephemeral key (NOT the master key)
	// The ephemeral key signs the token to bind it cryptographically
	ephemeralSigner, err := cose.NewEd25519Signer(proofResp.EphemeralPrivateKey.Key())
	if err != nil {
		log.Printf("Failed to create COSE signer: %v", err)
		http.Error(w, `{"error": "Failed to create token signature"}`, http.StatusInternalServerError)
		return
	}
	defer ephemeralSigner.Destroy()

	// Encode token in SIG1 wire format
	sig1Wire, err := signet.EncodeSIG1(token, ephemeralSigner)
	if err != nil {
		log.Printf("Failed to encode SIG1: %v", err)
		http.Error(w, `{"error": "Failed to encode token"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token_id":          tokenID,
		"token":             sig1Wire, // Now in SIG1 format instead of raw CBOR
		"ephemeral_public":  base64.RawURLEncoding.EncodeToString(ephemeralPub),
		"ephemeral_private": base64.RawURLEncoding.EncodeToString(proofResp.EphemeralPrivateKey.Key()),
		"binding_signature": base64.RawURLEncoding.EncodeToString(proofResp.Proof.BindingSignature),
		"master_public":     base64.RawURLEncoding.EncodeToString(serverMasterPub),
		"expires_at":        token.ExpiresAt,
		"purpose":           req.Purpose,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)

	log.Printf("✅ Issued token %s for purpose: %s", tokenID, req.Purpose)
}

// protectedHandler requires proper Signet proof with two-step verification
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the Signet-Proof header
	proofHeader := r.Header.Get("Signet-Proof")
	if proofHeader == "" {
		http.Error(w, `{"error": "Missing Signet-Proof header"}`, http.StatusUnauthorized)
		return
	}

	// Parse the proof components
	proof, err := header.ParseSignetProof(proofHeader)
	if err != nil {
		log.Printf("Invalid proof format: %v", err)
		http.Error(w, `{"error": "Invalid proof format"}`, http.StatusUnauthorized)
		return
	}

	// Extract token ID from full JTI (use full hash to prevent collisions)
	tokenID := hex.EncodeToString(proof.JTI)

	// Retrieve token record
	record, exists := tokenRegistry.Get(tokenID)

	// Timing Attack Mitigation: Always perform verification to prevent timing leaks
	// If the token doesn't exist, we still do a dummy verification that takes
	// similar time to real verification. This prevents attackers from distinguishing
	// between "token doesn't exist" (fast) and "token exists but wrong sig" (slow).
	if !exists {
		// Create dummy data that mimics real verification timing
		dummyPub, dummyPriv, _ := ed25519.GenerateKey(rand.Reader)
		dummyProof := &epr.EphemeralProof{
			EphemeralPublicKey: dummyPub,
			BindingSignature:   make([]byte, ed25519.SignatureSize),
		}
		dummyCanonical := createCanonicalRequest(r, proof)
		verifier := epr.NewVerifier()
		// Perform dummy verification (will fail, but takes same time as real verification)
		_ = verifier.VerifyProof(
			context.Background(),
			dummyProof,
			dummyPriv, // Wrong key type, but timing is similar
			time.Now().Unix()+300,
			"dummy-purpose",
			dummyCanonical,
			proof.Signature,
		)
		// Now return the "token not found" error (but timing matches real verification)
		log.Printf("Token not found: %s", tokenID)
		http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Check token validity (includes NotBefore and ExpiresAt)
	if !record.Token.IsValid() {
		if record.Token.IsExpired() {
			log.Printf("Token expired: %s", tokenID)
			http.Error(w, `{"error": "Token expired"}`, http.StatusUnauthorized)
		} else {
			log.Printf("Token not yet valid: %s", tokenID)
			http.Error(w, `{"error": "Token not yet valid"}`, http.StatusUnauthorized)
		}
		return
	}

	// Check clock skew (±30 seconds)
	now := time.Now().Unix()
	if proof.Timestamp < now-30 || proof.Timestamp > now+30 {
		log.Printf("Clock skew detected for token %s: timestamp %d, server time %d", tokenID, proof.Timestamp, now)
		http.Error(w, `{"error": "Clock skew detected"}`, http.StatusUnauthorized)
		return
	}

	// Check replay attack
	if err := nonceTracker.CheckAndStore(tokenID, proof.Timestamp); err != nil {
		log.Printf("Replay detected for token %s: %v", tokenID, err)
		http.Error(w, `{"error": "Replay detected"}`, http.StatusUnauthorized)
		return
	}

	// Reconstruct ephemeral proof for verification
	ephemeralProof := &epr.EphemeralProof{
		EphemeralPublicKey: record.EphemeralPublicKey,
		BindingSignature:   record.BindingSignature,
	}

	// Canonicalize the request (must match client's canonicalization)
	canonical := createCanonicalRequest(r, proof)

	// Perform full two-step verification
	verifier := epr.NewVerifier()
	err = verifier.VerifyProof(
		context.Background(),
		ephemeralProof,
		record.MasterPublicKey,
		record.Token.ExpiresAt,
		record.Purpose,
		canonical,
		proof.Signature,
	)

	if err != nil {
		log.Printf("❌ Cryptographic verification failed for token %s: %v", tokenID, err)
		http.Error(w, `{"error": "Invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// Success!
	log.Printf("✅ Request verified for token %s (purpose: %s)", tokenID, record.Purpose)

	response := map[string]interface{}{
		"status":    "authenticated",
		"token_id":  tokenID,
		"timestamp": proof.Timestamp,
		"purpose":   record.Purpose,
		"message":   "Successfully authenticated with Signet two-step verification!",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// createCanonicalRequest creates the canonical representation of the request
func createCanonicalRequest(r *http.Request, proof *header.SignetProof) []byte {
	// This must match EXACTLY what the client signs
	// Format: METHOD|PATH|TIMESTAMP|NONCE_BASE64
	canonical := fmt.Sprintf("%s|%s|%d|%s",
		r.Method,
		r.URL.Path,
		proof.Timestamp,
		base64.RawURLEncoding.EncodeToString(proof.Nonce),
	)
	return []byte(canonical)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	masterHash := sha256.Sum256(serverMasterPub)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"auth":   "Signet PoP with two-step verification",
		"master_key": map[string]string{
			"algorithm": "Ed25519",
			"hash":      hex.EncodeToString(masterHash[:8]),
		},
	})
}

func main() {
	http.HandleFunc("/issue-token", issueTokenHandler)
	http.HandleFunc("/protected", protectedHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("🔐 Signet HTTP Auth Demo Server (Two-Step Verification)")
	fmt.Println("========================================================")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /health      - Health check (no auth)")
	fmt.Println("  POST /issue-token - Issue a new Signet token with ephemeral binding")
	fmt.Println("  GET  /protected   - Protected endpoint (requires valid Signet proof)")
	fmt.Println("")
	fmt.Println("Security Properties Enforced:")
	fmt.Println("  ✓ Two-step cryptographic verification (master→ephemeral→request)")
	fmt.Println("  ✓ Token-based ephemeral key binding")
	fmt.Println("  ✓ Replay attack prevention via nonce tracking")
	fmt.Println("  ✓ Time-bound tokens (5-minute validity)")
	fmt.Println("  ✓ Purpose-specific ephemeral keys")
	fmt.Println("")
	masterKeyHash := sha256.Sum256(serverMasterPub)
	fmt.Printf("Server Master Key (first 8 bytes): %x\n", masterKeyHash[:8])
	fmt.Println("")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	fmt.Printf("Starting server on %s...\n", addr)

	log.Fatal(http.ListenAndServe(addr, nil))
}
