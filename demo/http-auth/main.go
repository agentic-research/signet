package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jamestexas/signet/pkg/http/header"
)

// NonceTracker prevents replay attacks by tracking nonces per JTI
type NonceTracker struct {
	mu     sync.RWMutex
	seen   map[string]time.Time // jti -> last timestamp
	window time.Duration        // How long to remember nonces
}

func NewNonceTracker() *NonceTracker {
	nt := &NonceTracker{
		seen:   make(map[string]time.Time),
		window: 5 * time.Minute,
	}
	// Clean up old entries periodically
	go nt.cleanup()
	return nt
}

func (nt *NonceTracker) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		nt.mu.Lock()
		now := time.Now()
		for jti, ts := range nt.seen {
			if now.Sub(ts) > nt.window {
				delete(nt.seen, jti)
			}
		}
		nt.mu.Unlock()
	}
}

// CheckMonotonic ensures timestamp is strictly increasing for this JTI
func (nt *NonceTracker) CheckMonotonic(jti string, timestamp time.Time) error {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	// Check clock skew window (±30 seconds)
	now := time.Now()
	if timestamp.Before(now.Add(-30*time.Second)) || timestamp.After(now.Add(30*time.Second)) {
		return fmt.Errorf("timestamp outside acceptable window")
	}

	lastSeen, exists := nt.seen[jti]
	if exists && !timestamp.After(lastSeen) { // This means timestamp <= lastSeen
		return fmt.Errorf("replay detected: timestamp not strictly monotonic")
	}

	nt.seen[jti] = timestamp
	return nil
}

// Simple in-memory key storage for demo
var (
	// Master key that would normally be in secure storage
	masterPriv, masterPub = generateKeys()
	nonceTracker          = NewNonceTracker()
)

func generateKeys() (ed25519.PrivateKey, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the Signet-Proof header
	proofHeader := r.Header.Get("Signet-Proof")
	if proofHeader == "" {
		http.Error(w, `{"error": "Missing Signet-Proof header"}`, http.StatusUnauthorized)
		return
	}

	// Parse the proof
	proof, err := header.ParseSignetProof(proofHeader)
	if err != nil {
		log.Printf("Invalid proof: %v", err) // Log full error server-side
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Extract JTI and timestamp
	jti := base64.RawURLEncoding.EncodeToString(proof.JTI)

	// Check monotonic timestamp for this JTI (replay protection)
	if err := nonceTracker.CheckMonotonic(jti, time.Unix(proof.Timestamp, 0)); err != nil {
		log.Printf("Replay protection triggered for JTI %x: %v", proof.JTI[:1], err) // Log only 1 byte
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Verify the signature (simplified - in real implementation would verify against token)
	// For demo, we're just checking the proof structure is valid
	if len(proof.Signature) < 64 {
		http.Error(w, `{"error": "Invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// Success!
	response := map[string]interface{}{
		"status":    "authenticated",
		"timestamp": proof.Timestamp,
		"message":   "Successfully authenticated with Signet proof!",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"auth":   "Signet PoP required at /protected",
	})
}

func main() {
	http.HandleFunc("/protected", protectedHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("🔐 Signet HTTP Auth Demo Server")
	fmt.Println("================================")
	fmt.Println("Endpoints:")
	fmt.Println("  GET /health    - Health check (no auth)")
	fmt.Println("  GET /protected - Protected endpoint (requires Signet-Proof)")
	fmt.Println("")
	fmt.Println("The server enforces:")
	fmt.Println("  ✓ Signet-Proof header validation")
	fmt.Println("  ✓ Monotonic timestamp per JTI (replay protection)")
	fmt.Println("  ✓ 5-minute sliding window for nonce tracking")
	fmt.Println("")
	fmt.Println("Starting server on :8080...")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
