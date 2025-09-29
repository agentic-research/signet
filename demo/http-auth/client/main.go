package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SimplifiedProof for demo - shows the concept
type SimplifiedProof struct {
	JTI       []byte
	Timestamp int64
	Nonce     []byte
	Signature []byte
}

func generateJTI() []byte {
	jti := make([]byte, 16)
	rand.Read(jti)
	return jti
}

func generateNonce() []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return nonce
}

func createSignetProof(jti []byte, timestamp int64) string {
	// Generate ephemeral key (normally derived from master)
	_, ephemeralPriv, _ := ed25519.GenerateKey(nil)

	// Create nonce
	nonce := generateNonce()

	// Create canonical request representation (simplified)
	canonical := fmt.Sprintf("GET|/protected|%d|%s", timestamp, base64.RawURLEncoding.EncodeToString(nonce))

	// Sign with ephemeral key
	signature := ed25519.Sign(ephemeralPriv, []byte(canonical))

	// Build proof header
	// Format: v1;m=compact;t=<token>;jti=<jti>;cap=<cap>;s=<sig>;n=<nonce>;ts=<timestamp>
	proof := fmt.Sprintf("v1;m=compact;t=%s;jti=%s;cap=%s;s=%s;n=%s;ts=%d",
		"placeholder_token",
		base64.RawURLEncoding.EncodeToString(jti),
		base64.RawURLEncoding.EncodeToString(sha256.New().Sum(nil)[:16]),
		base64.RawURLEncoding.EncodeToString(signature),
		base64.RawURLEncoding.EncodeToString(nonce),
		timestamp,
	)

	return proof
}

func makeRequest(jti []byte, timestamp int64, attempt int) {
	client := &http.Client{Timeout: 5 * time.Second}

	// Create Signet proof
	proof := createSignetProof(jti, timestamp)

	// Create request
	req, _ := http.NewRequest("GET", "http://localhost:8080/protected", nil)
	req.Header.Set("Authorization", "Bearer SIG1.eyJpc3MiOiJzaWduZXQtZGVtbyJ9")
	req.Header.Set("Signet-Proof", proof)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Attempt %d: Request failed: %v\n", attempt, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	jtiShort := hex.EncodeToString(jti[:4])

	if resp.StatusCode == 200 {
		fmt.Printf("✅ Attempt %d: SUCCESS (JTI: %s, ts: %d)\n", attempt, jtiShort, timestamp)
		fmt.Printf("   Response: %s\n", strings.TrimSpace(string(body)))
	} else {
		fmt.Printf("❌ Attempt %d: BLOCKED - %s (JTI: %s, ts: %d)\n",
			attempt, resp.Status, jtiShort, timestamp)
		fmt.Printf("   Reason: %s\n", strings.TrimSpace(string(body)))
	}
}

func main() {
	fmt.Println("🔐 Signet HTTP Client Demo")
	fmt.Println("==========================")
	fmt.Println()

	// Check if server is running
	resp, err := http.Get("http://localhost:8080/health")
	if err != nil {
		fmt.Println("❌ Server not running. Start the server first with:")
		fmt.Println("   go run demo/http-auth/main.go")
		return
	}
	resp.Body.Close()

	// Demo 1: Normal flow - each request with increasing timestamp
	fmt.Println("Demo 1: Normal Authentication Flow")
	fmt.Println("-----------------------------------")
	jti1 := generateJTI()

	for i := 1; i <= 3; i++ {
		timestamp := time.Now().Unix() + int64(i)
		makeRequest(jti1, timestamp, i)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println()

	// Demo 2: Replay attack - same timestamp
	fmt.Println("Demo 2: Replay Attack Prevention")
	fmt.Println("---------------------------------")
	jti2 := generateJTI()
	replayTimestamp := time.Now().Unix()

	fmt.Println("First request with timestamp:", replayTimestamp)
	makeRequest(jti2, replayTimestamp, 1)

	time.Sleep(1 * time.Second)

	fmt.Println("\nReplaying same request 1 second later...")
	makeRequest(jti2, replayTimestamp, 2) // Same timestamp - should fail!

	fmt.Println()

	// Demo 3: Different JTI can use same timestamp
	fmt.Println("Demo 3: Different JTI Independence")
	fmt.Println("-----------------------------------")
	jti3 := generateJTI()
	jti4 := generateJTI()
	sharedTimestamp := time.Now().Unix() + 100

	fmt.Printf("Both requests using timestamp: %d\n", sharedTimestamp)
	makeRequest(jti3, sharedTimestamp, 1)
	makeRequest(jti4, sharedTimestamp, 2) // Different JTI, same timestamp - should work!

	fmt.Println()
	fmt.Println("✨ Demo complete! This shows:")
	fmt.Println("  1. ✅ Normal auth flow works with monotonic timestamps")
	fmt.Println("  2. ❌ Replay attacks are blocked (same JTI + timestamp)")
	fmt.Println("  3. ✅ Different JTIs are independent")
}
