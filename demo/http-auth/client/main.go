package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/epr"
	"github.com/jamestexas/signet/pkg/signet"
)

// TokenInfo holds the cryptographic material received from server
type TokenInfo struct {
	TokenID          string
	Token            *signet.Token
	EphemeralPublic  ed25519.PublicKey
	EphemeralPrivate ed25519.PrivateKey
	BindingSignature []byte
	MasterPublic     ed25519.PublicKey
	Purpose          string
}

// getServerURL returns the server URL from environment or default
func getServerURL() string {
	if url := os.Getenv("SERVER_URL"); url != "" {
		return url
	}
	return "http://localhost:8080"
}

// requestToken gets a new token from the server with proper ephemeral binding
func requestToken(purpose string) (*TokenInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	serverURL := getServerURL()

	reqBody := map[string]string{
		"purpose": purpose,
	}

	bodyBytes, _ := json.Marshal(reqBody)
	resp, err := client.Post(serverURL+"/issue-token", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %s - %s", resp.Status, body)
	}

	var response struct {
		TokenID          string `json:"token_id"`
		Token            string `json:"token"`
		EphemeralPublic  string `json:"ephemeral_public"`
		EphemeralPrivate string `json:"ephemeral_private"`
		BindingSignature string `json:"binding_signature"`
		MasterPublic     string `json:"master_public"`
		CapabilityID     string `json:"capability_id"`
		TokenJTI         string `json:"token_jti"`
		ExpiresAt        int64  `json:"expires_at"`
		Purpose          string `json:"purpose"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Decode all the cryptographic material
	tokenBytes, _ := base64.RawURLEncoding.DecodeString(response.Token)
	token, err := signet.Unmarshal(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	ephPub, _ := base64.RawURLEncoding.DecodeString(response.EphemeralPublic)
	ephPriv, _ := base64.RawURLEncoding.DecodeString(response.EphemeralPrivate)
	bindingSig, _ := base64.RawURLEncoding.DecodeString(response.BindingSignature)
	masterPub, _ := base64.RawURLEncoding.DecodeString(response.MasterPublic)

	return &TokenInfo{
		TokenID:          response.TokenID,
		Token:            token,
		EphemeralPublic:  ed25519.PublicKey(ephPub),
		EphemeralPrivate: ed25519.PrivateKey(ephPriv),
		BindingSignature: bindingSig,
		MasterPublic:     ed25519.PublicKey(masterPub),
		Purpose:          response.Purpose,
	}, nil
}

// createSignetProof creates a proof using the ephemeral private key
func createSignetProof(tokenInfo *TokenInfo, timestamp int64) string {
	// Use the token's nonce (legacy flow - will be client-generated in future revisions)
	nonce := tokenInfo.Token.Nonce

	// Create canonical request representation (must match server's canonicalization)
	canonical := fmt.Sprintf("GET|/protected|%d|%s",
		timestamp,
		base64.RawURLEncoding.EncodeToString(nonce))

	// Sign with ephemeral private key
	signature := ed25519.Sign(tokenInfo.EphemeralPrivate, []byte(canonical))

	// Calculate ephemeral key hash
	ephKeyHash := sha256.Sum256(tokenInfo.EphemeralPublic)

	// Create proof header value
	// Format: v1;m=compact;jti=<base64>;cap=<base64>;p=<base64>;k=<base64>;ts=<timestamp>;n=<base64_nonce>;s=<base64_sig>
	jtiB64 := base64.RawURLEncoding.EncodeToString(tokenInfo.Token.JTI)
	capB64 := base64.RawURLEncoding.EncodeToString(tokenInfo.Token.CapabilityID)
	proofB64 := base64.RawURLEncoding.EncodeToString(tokenInfo.BindingSignature)
	keyHashB64 := base64.RawURLEncoding.EncodeToString(ephKeyHash[:])
	proof := fmt.Sprintf("v1;m=compact;jti=%s;cap=%s;p=%s;k=%s;ts=%d;n=%s;s=%s",
		jtiB64,
		capB64,
		proofB64,
		keyHashB64,
		timestamp,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(signature))

	return proof
}

// makeAuthenticatedRequest makes a request with Signet proof
func makeAuthenticatedRequest(tokenInfo *TokenInfo, timestamp int64, attempt int) {
	client := &http.Client{Timeout: 5 * time.Second}
	serverURL := getServerURL()

	// Create Signet proof
	proof := createSignetProof(tokenInfo, timestamp)

	// Create request
	req, _ := http.NewRequest("GET", serverURL+"/protected", nil)
	req.Header.Set("Signet-Proof", proof)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Attempt %d failed: %v\n", attempt, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		_ = json.Unmarshal(body, &result)
		fmt.Printf("  ✅ Attempt %d: Authenticated! Token: %s, Purpose: %s\n",
			attempt, tokenInfo.TokenID, result["purpose"])
	} else {
		fmt.Printf("  ❌ Attempt %d: Failed with status %d: %s\n",
			attempt, resp.StatusCode, string(body))
	}
}

// verifyLocalBinding demonstrates local verification of the binding
func verifyLocalBinding(tokenInfo *TokenInfo) error {
	// Create ephemeral proof structure
	ephemeralProof := &epr.EphemeralProof{
		EphemeralPublicKey: tokenInfo.EphemeralPublic,
		BindingSignature:   tokenInfo.BindingSignature,
	}

	// Verify the binding locally
	verifier := epr.NewVerifier()
	err := verifier.VerifyBinding(
		context.Background(),
		ephemeralProof,
		tokenInfo.MasterPublic,
		tokenInfo.Token.ExpiresAt,
		tokenInfo.Purpose,
	)

	if err != nil {
		return fmt.Errorf("binding verification failed: %w", err)
	}

	return nil
}

// zeroKey securely zeros out a private key in memory
func zeroKey(key []byte) {
	if key == nil {
		return
	}
	// Overwrite the key bytes with zeros
	for i := range key {
		key[i] = 0
	}
	// Prevent compiler optimization from removing the zeroing
	// runtime.KeepAlive ensures the key is not garbage collected before zeroing completes
	runtime.KeepAlive(key)
}

func main() {
	fmt.Println("🔐 Signet HTTP Auth Demo Client")
	fmt.Println("================================")
	fmt.Println()

	serverURL := getServerURL()

	// Wait for server to be ready (important in Docker)
	for i := 0; i < 30; i++ {
		if resp, err := http.Get(serverURL + "/health"); err == nil {
			resp.Body.Close()
			break
		}
		if i == 29 {
			fmt.Printf("❌ Server at %s is not responding after 30 seconds\n", serverURL)
			return
		}
		time.Sleep(1 * time.Second)
	}

	// Check server health
	resp, err := http.Get(serverURL + "/health")
	if err != nil {
		fmt.Printf("❌ Server is not running: %v\n", err)
		fmt.Println("Please start the server first: go run demo/http-auth/server/main.go")
		return
	}
	resp.Body.Close()
	fmt.Println("✅ Server is healthy")
	fmt.Println()

	// Demo 1: Full two-step verification flow
	fmt.Println("Demo 1: Two-Step Cryptographic Verification")
	fmt.Println("--------------------------------------------")

	// Request a token from the server
	fmt.Println("Step 1: Requesting token with ephemeral key binding...")
	tokenInfo, err := requestToken("api-access")
	if err != nil {
		fmt.Printf("❌ Failed to get token: %v\n", err)
		return
	}

	fmt.Printf("✅ Received token: %s\n", tokenInfo.TokenID)
	fmt.Printf("   - Purpose: %s\n", tokenInfo.Purpose)
	fmt.Printf("   - Expires: %s\n", time.Unix(tokenInfo.Token.ExpiresAt, 0).Format(time.RFC3339))
	fmt.Printf("   - Master key hash: %x\n", tokenInfo.Token.ConfirmationID[:8])
	fmt.Printf("   - Ephemeral key hash: %x\n", tokenInfo.Token.EphemeralKeyID[:8])
	fmt.Println()

	// Verify the binding locally (demonstrates client-side verification)
	fmt.Println("Step 2: Verifying binding signature locally...")
	if err := verifyLocalBinding(tokenInfo); err != nil {
		fmt.Printf("❌ Local binding verification failed: %v\n", err)
		return
	}
	fmt.Println("✅ Binding signature verified (master→ephemeral)")
	fmt.Println()

	// Make authenticated requests
	fmt.Println("Step 3: Making authenticated requests...")
	for i := 1; i <= 3; i++ {
		timestamp := time.Now().Unix() + int64(i)
		makeAuthenticatedRequest(tokenInfo, timestamp, i)
		time.Sleep(500 * time.Millisecond)
	}

	// Zero out the ephemeral private key after use
	defer zeroKey(tokenInfo.EphemeralPrivate)

	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println()

	// Demo 2: Replay attack prevention
	fmt.Println("Demo 2: Replay Attack Prevention")
	fmt.Println("---------------------------------")

	// Get a new token for replay demo
	tokenInfo2, err := requestToken("replay-test")
	if err != nil {
		fmt.Printf("❌ Failed to get token: %v\n", err)
		return
	}
	fmt.Printf("✅ Got new token: %s\n", tokenInfo2.TokenID)

	replayTimestamp := time.Now().Unix()
	fmt.Printf("\nFirst request with timestamp: %d\n", replayTimestamp)
	makeAuthenticatedRequest(tokenInfo2, replayTimestamp, 1)

	time.Sleep(1 * time.Second)

	fmt.Println("\nReplaying same request 1 second later...")
	makeAuthenticatedRequest(tokenInfo2, replayTimestamp, 2) // Should fail!

	// Zero out the ephemeral private key after use
	defer zeroKey(tokenInfo2.EphemeralPrivate)

	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println()

	// Demo 3: Token independence
	fmt.Println("Demo 3: Token Independence")
	fmt.Println("--------------------------")

	// Request two different tokens
	token3, _ := requestToken("service-a")
	token4, _ := requestToken("service-b")
	sharedTimestamp := time.Now().Unix() + 100

	fmt.Printf("Token A: %s (purpose: %s)\n", token3.TokenID, token3.Purpose)
	fmt.Printf("Token B: %s (purpose: %s)\n", token4.TokenID, token4.Purpose)
	fmt.Printf("Both using timestamp: %d\n", sharedTimestamp)
	fmt.Println()

	makeAuthenticatedRequest(token3, sharedTimestamp, 1)
	makeAuthenticatedRequest(token4, sharedTimestamp, 2) // Different token, same timestamp - should work!

	// Zero out both ephemeral private keys after use
	defer zeroKey(token3.EphemeralPrivate)
	defer zeroKey(token4.EphemeralPrivate)

	fmt.Println()
	fmt.Println("✨ Demo complete! This demonstrates:")
	fmt.Println("  1. ✅ Full two-step cryptographic verification (master→ephemeral→request)")
	fmt.Println("  2. ✅ Token-based ephemeral key binding with proper CBOR encoding")
	fmt.Println("  3. ✅ Client-side binding verification capability")
	fmt.Println("  4. ❌ Replay attacks are blocked (same token + timestamp)")
	fmt.Println("  5. ✅ Different tokens are independent (different purposes)")
	fmt.Println("  6. ✅ Purpose-specific ephemeral keys enforcement")

	// Show cryptographic chain
	fmt.Println()
	fmt.Println("🔗 Cryptographic Chain of Trust:")
	fmt.Println("  Master Key → [signs] → Ephemeral Key Binding")
	fmt.Println("  Ephemeral Key → [signs] → Request")
	fmt.Println("  Server verifies BOTH signatures in sequence")
}
