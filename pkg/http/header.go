package http

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/crypto/epr"
)

// ProofHeader represents the parsed Signet-Proof HTTP header
type ProofHeader struct {
	Version          string             // Protocol version (e.g., "v1")
	Token            []byte             // CBOR-encoded Signet token
	EphemeralProof   *epr.EphemeralProof // Ephemeral proof containing binding signature
	RequestSignature []byte             // Signature over canonicalized request
	Nonce            []byte             // Request-specific nonce
	Timestamp        int64              // Request timestamp (Unix)
}

// ParseProofHeader parses a Signet-Proof header value
// Format: v1;t=<token>;p=<proof>;s=<signature>;n=<nonce>
func ParseProofHeader(headerValue string) (*ProofHeader, error) {
	if headerValue == "" {
		return nil, fmt.Errorf("empty proof header")
	}

	parts := strings.Split(headerValue, ";")
	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid proof header format: expected at least 5 parts, got %d", len(parts))
	}

	// Parse version
	version := strings.TrimSpace(parts[0])
	if version != "v1" {
		return nil, fmt.Errorf("unsupported proof version: %s", version)
	}

	header := &ProofHeader{
		Version: version,
		EphemeralProof: &epr.EphemeralProof{},
	}

	// Parse key-value pairs
	for i := 1; i < len(parts); i++ {
		kv := strings.SplitN(parts[i], "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", parts[i])
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "t": // Token (base64url-encoded CBOR)
			token, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid token encoding: %w", err)
			}
			header.Token = token

		case "p": // Proof (base64url-encoded binding signature)
			proof, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid proof encoding: %w", err)
			}
			header.EphemeralProof.BindingSignature = proof

		case "k": // Ephemeral public key (base64url-encoded)
			key, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid ephemeral key encoding: %w", err)
			}
			header.EphemeralProof.EphemeralPublicKey = key

		case "s": // Request signature (base64url-encoded)
			sig, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid signature encoding: %w", err)
			}
			header.RequestSignature = sig

		case "n": // Nonce (base64url-encoded)
			nonce, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid nonce encoding: %w", err)
			}
			header.Nonce = nonce

		case "ts": // Timestamp
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp: %w", err)
			}
			header.Timestamp = ts

		default:
			// Ignore unknown fields for forward compatibility
		}
	}

	// Validate required fields
	if header.Token == nil {
		return nil, fmt.Errorf("missing token in proof header")
	}
	if header.EphemeralProof.BindingSignature == nil {
		return nil, fmt.Errorf("missing proof in proof header")
	}
	if header.EphemeralProof.EphemeralPublicKey == nil {
		return nil, fmt.Errorf("missing ephemeral key in proof header")
	}
	if header.RequestSignature == nil {
		return nil, fmt.Errorf("missing signature in proof header")
	}
	if header.Nonce == nil {
		return nil, fmt.Errorf("missing nonce in proof header")
	}
	if header.Timestamp == 0 {
		return nil, fmt.Errorf("missing timestamp in proof header")
	}

	return header, nil
}

// FormatProofHeader formats a ProofHeader into a header value string
func FormatProofHeader(header *ProofHeader) string {
	var parts []string

	// Version is always first
	parts = append(parts, header.Version)

	// Add token
	if header.Token != nil {
		tokenStr := base64.RawURLEncoding.EncodeToString(header.Token)
		parts = append(parts, fmt.Sprintf("t=%s", tokenStr))
	}

	// Add proof (binding signature)
	if header.EphemeralProof != nil && header.EphemeralProof.BindingSignature != nil {
		proofStr := base64.RawURLEncoding.EncodeToString(header.EphemeralProof.BindingSignature)
		parts = append(parts, fmt.Sprintf("p=%s", proofStr))
	}

	// Add ephemeral key
	if header.EphemeralProof != nil && header.EphemeralProof.EphemeralPublicKey != nil {
		var keyBytes []byte

		// Handle different key types
		switch k := header.EphemeralProof.EphemeralPublicKey.(type) {
		case []byte:
			keyBytes = k
		case ed25519.PublicKey:
			keyBytes = []byte(k)
		default:
			// Try direct conversion for other types
			if kb, ok := header.EphemeralProof.EphemeralPublicKey.([]byte); ok {
				keyBytes = kb
			}
		}

		if len(keyBytes) > 0 {
			keyStr := base64.RawURLEncoding.EncodeToString(keyBytes)
			parts = append(parts, fmt.Sprintf("k=%s", keyStr))
		}
	}

	// Add request signature
	if header.RequestSignature != nil {
		sigStr := base64.RawURLEncoding.EncodeToString(header.RequestSignature)
		parts = append(parts, fmt.Sprintf("s=%s", sigStr))
	}

	// Add nonce
	if header.Nonce != nil {
		nonceStr := base64.RawURLEncoding.EncodeToString(header.Nonce)
		parts = append(parts, fmt.Sprintf("n=%s", nonceStr))
	}

	// Add timestamp
	if header.Timestamp > 0 {
		parts = append(parts, fmt.Sprintf("ts=%d", header.Timestamp))
	}

	return strings.Join(parts, ";")
}

// SignetToken represents the CBOR-encoded token structure
type SignetToken struct {
	IssuerID       string `cbor:"1,keyasint"`
	ConfirmationID []byte `cbor:"2,keyasint"`
	ExpiresAt      int64  `cbor:"3,keyasint"`
	Nonce          []byte `cbor:"4,keyasint"`
	EphemeralKeyID []byte `cbor:"5,keyasint"`
	NotBefore      int64  `cbor:"6,keyasint"`
}

// EncodeToken encodes a SignetToken to CBOR
func EncodeToken(token *SignetToken) ([]byte, error) {
	return cbor.Marshal(token)
}

// DecodeToken decodes CBOR bytes into a SignetToken
func DecodeToken(data []byte) (*SignetToken, error) {
	var token SignetToken
	err := cbor.Unmarshal(data, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}
	return &token, nil
}

// CanonicalizeRequest creates a canonical representation of the HTTP request for signing
func CanonicalizeRequest(method, uri string, timestamp int64, nonce []byte) []byte {
	// Format: <method>\n<uri>\n<timestamp>\n<nonce>
	canonical := fmt.Sprintf("%s\n%s\n%d\n", method, uri, timestamp)
	return append([]byte(canonical), nonce...)
}

// ValidateTimestamp checks if a timestamp is within acceptable bounds
func ValidateTimestamp(timestamp int64, clockSkew time.Duration) error {
	now := time.Now().Unix()
	diff := timestamp - now
	if diff < 0 {
		diff = -diff
	}

	if diff > int64(clockSkew.Seconds()) {
		return fmt.Errorf("timestamp outside acceptable window: diff=%ds, max=%ds", diff, int64(clockSkew.Seconds()))
	}

	return nil
}