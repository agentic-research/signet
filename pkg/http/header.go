package http

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jamestexas/signet/pkg/crypto/epr"
)

// ProofHeader represents the parsed Signet-Proof HTTP header with v1.0 security enhancements
type ProofHeader struct {
	Version          string              // Protocol version (e.g., "v1")
	Mode             string              // "full" or "compact"
	Token            []byte              // Full SIG1 token (full mode) or CBOR (compact)
	JTI              []byte              // Token ID (16 bytes) - REQUIRED
	CapabilityID     []byte              // Capability hash (16 bytes) - REQUIRED
	EphemeralKeyHash []byte              // Privacy-preserving kid = H(jti||ephemeralKey)
	EphemeralProof   *epr.EphemeralProof // Ephemeral proof containing binding signature
	RequestSignature []byte              // Signature over canonicalized request
	Nonce            []byte              // Request-specific nonce (16 bytes)
	Timestamp        int64               // Request timestamp (Unix)
	BodyDigest       []byte              // Blake3 of request body (for POST/PUT)
	Critical         []string            // Must-understand extension fields
}

// ParseProofHeader parses a Signet-Proof header value with strict validation
// Format: v1;m=<mode>;t=<token>;jti=<jti>;cap=<cap_id>;...
func ParseProofHeader(headerValue string) (*ProofHeader, error) {
	if headerValue == "" {
		return nil, fmt.Errorf("empty proof header")
	}

	parts := strings.Split(headerValue, ";")
	if len(parts) < 7 { // Minimum: version, mode, token, jti, cap, sig, nonce, ts
		return nil, fmt.Errorf("invalid proof header format: expected at least 7 parts, got %d", len(parts))
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

	// Track which fields we've seen for strict ordering
	seenFields := make(map[string]bool)

	// Parse key-value pairs
	for i := 1; i < len(parts); i++ {
		kv := strings.SplitN(parts[i], "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", parts[i])
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		// Check for duplicate fields
		if seenFields[key] {
			return nil, fmt.Errorf("duplicate field: %s", key)
		}
		seenFields[key] = true

		switch key {
		case "m": // Mode (full or compact)
			if value != "full" && value != "compact" {
				return nil, fmt.Errorf("invalid mode: %s", value)
			}
			header.Mode = value

		case "t": // Token
			token, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid token encoding: %w", err)
			}
			header.Token = token

		case "jti": // Token ID (REQUIRED)
			jti, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid jti encoding: %w", err)
			}
			if len(jti) != 16 {
				return nil, fmt.Errorf("invalid jti length: expected 16 bytes, got %d", len(jti))
			}
			header.JTI = jti

		case "cap": // Capability ID (REQUIRED)
			capID, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid cap_id encoding: %w", err)
			}
			if len(capID) != 16 {
				return nil, fmt.Errorf("invalid cap_id length: expected 16 bytes, got %d", len(capID))
			}
			header.CapabilityID = capID

		case "p": // Proof (base64url-encoded binding signature)
			proof, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid proof encoding: %w", err)
			}
			header.EphemeralProof.BindingSignature = proof

		case "k": // Ephemeral key hash (privacy-preserving)
			keyHash, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid key hash encoding: %w", err)
			}
			if len(keyHash) != 32 {
				return nil, fmt.Errorf("invalid key hash length: expected 32 bytes, got %d", len(keyHash))
			}
			header.EphemeralKeyHash = keyHash

		case "s": // Request signature (base64url-encoded)
			sig, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid signature encoding: %w", err)
			}
			header.RequestSignature = sig

		case "n": // Nonce
			nonce, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid nonce encoding: %w", err)
			}
			if len(nonce) != 16 {
				return nil, fmt.Errorf("invalid nonce length: expected 16 bytes, got %d", len(nonce))
			}
			header.Nonce = nonce

		case "ts": // Timestamp
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp: %w", err)
			}
			header.Timestamp = ts

		case "bd": // Body digest (optional, for POST/PUT)
			digest, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid body digest encoding: %w", err)
			}
			header.BodyDigest = digest

		case "crit": // Critical fields
			header.Critical = strings.Split(value, ",")

		default:
			// Ignore unknown fields for forward compatibility
		}
	}

	// Validate critical fields if present
	for _, critField := range header.Critical {
		if !seenFields[critField] {
			return nil, fmt.Errorf("critical field not present: %s", critField)
		}
	}

	// Validate required fields based on mode
	if header.Mode == "" {
		header.Mode = "compact" // Default for backwards compatibility
	}
	if header.Token == nil {
		return nil, fmt.Errorf("missing token in proof header")
	}
	if header.JTI == nil {
		return nil, fmt.Errorf("missing jti in proof header")
	}
	if header.CapabilityID == nil {
		return nil, fmt.Errorf("missing cap_id in proof header")
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

	// Mode-specific validation
	if header.Mode == "compact" {
		if header.EphemeralProof.BindingSignature == nil {
			return nil, fmt.Errorf("missing proof in compact mode")
		}
		if header.EphemeralKeyHash == nil {
			return nil, fmt.Errorf("missing key hash in compact mode")
		}
	}

	return header, nil
}

// FormatProofHeader formats a ProofHeader into a header value string
func FormatProofHeader(header *ProofHeader) string {
	var parts []string

	// Version is always first
	parts = append(parts, header.Version)

	// Mode is always second
	if header.Mode == "" {
		header.Mode = "compact" // Default
	}
	parts = append(parts, fmt.Sprintf("m=%s", header.Mode))

	// Add token
	if header.Token != nil {
		tokenStr := base64.RawURLEncoding.EncodeToString(header.Token)
		parts = append(parts, fmt.Sprintf("t=%s", tokenStr))
	}

	// Add required fields in order
	if header.JTI != nil {
		jtiStr := base64.RawURLEncoding.EncodeToString(header.JTI)
		parts = append(parts, fmt.Sprintf("jti=%s", jtiStr))
	}

	if header.CapabilityID != nil {
		capStr := base64.RawURLEncoding.EncodeToString(header.CapabilityID)
		parts = append(parts, fmt.Sprintf("cap=%s", capStr))
	}

	// Add mode-specific fields
	if header.Mode == "compact" {
		if header.EphemeralProof != nil && header.EphemeralProof.BindingSignature != nil {
			proofStr := base64.RawURLEncoding.EncodeToString(header.EphemeralProof.BindingSignature)
			parts = append(parts, fmt.Sprintf("p=%s", proofStr))
		}

		if header.EphemeralKeyHash != nil {
			keyStr := base64.RawURLEncoding.EncodeToString(header.EphemeralKeyHash)
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

	// Add optional fields
	if header.BodyDigest != nil {
		bdStr := base64.RawURLEncoding.EncodeToString(header.BodyDigest)
		parts = append(parts, fmt.Sprintf("bd=%s", bdStr))
	}

	if len(header.Critical) > 0 {
		parts = append(parts, fmt.Sprintf("crit=%s", strings.Join(header.Critical, ",")))
	}

	return strings.Join(parts, ";")
}

// SignetToken represents the CBOR-encoded token structure
// Updated with all ADR-002 required fields
type SignetToken struct {
	IssuerID       uint64                 `cbor:"1,keyasint"`
	AudienceID     uint64                 `cbor:"2,keyasint,omitempty"`
	SubjectPPID    []byte                 `cbor:"3,keyasint"`  // Per-token pairwise pseudonym
	ExpiresAt      int64                  `cbor:"4,keyasint"`
	NotBefore      int64                  `cbor:"5,keyasint,omitempty"`
	IssuedAt       int64                  `cbor:"6,keyasint,omitempty"`
	CapabilityID   []byte                 `cbor:"7,keyasint"`  // 128-bit capability hash
	CapabilityVer  uint32                 `cbor:"8,keyasint"`  // major.minor encoded
	ConfirmationID []byte                 `cbor:"9,keyasint"`  // SHA-256 of bound key
	KeyID          uint64                 `cbor:"10,keyasint"`
	CapTokens      []uint64               `cbor:"11,keyasint,omitempty"`
	CapCustom      map[string]interface{} `cbor:"12,keyasint,omitempty"`
	JTI            []byte                 `cbor:"13,keyasint"` // Token ID
	Actor          map[string]interface{} `cbor:"14,keyasint,omitempty"`
	Delegator      map[string]interface{} `cbor:"15,keyasint,omitempty"`
	AudienceStr    string                 `cbor:"16,keyasint,omitempty"` // For debugging
}

// EncodeToken encodes a SignetToken to CBOR with deterministic encoding
func EncodeToken(token *SignetToken) ([]byte, error) {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(token)
}

// DecodeToken decodes CBOR bytes into a SignetToken with strict validation
func DecodeToken(data []byte) (*SignetToken, error) {
	var token SignetToken
	err := cbor.Unmarshal(data, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	// Validate required fields
	if token.JTI == nil || len(token.JTI) != 16 {
		return nil, fmt.Errorf("invalid jti in token")
	}
	if token.CapabilityID == nil || len(token.CapabilityID) != 16 {
		return nil, fmt.Errorf("invalid capability_id in token")
	}
	if token.SubjectPPID == nil || len(token.SubjectPPID) != 32 {
		return nil, fmt.Errorf("invalid subject_ppid in token")
	}
	if token.ConfirmationID == nil || len(token.ConfirmationID) != 32 {
		return nil, fmt.Errorf("invalid confirmation_id in token")
	}

	return &token, nil
}

// ComputeEphemeralKeyHash generates privacy-preserving key identifier
func ComputeEphemeralKeyHash(jti []byte, ephemeralKey ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write(jti)
	h.Write(ephemeralKey)
	return h.Sum(nil)
}

// ConstantTimeCompare performs constant-time comparison of signatures
func ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// CanonicalizeRequest creates a canonical representation of the HTTP request for signing
// Updated to include body digest for POST/PUT/PATCH
func CanonicalizeRequest(method, uri, host string, timestamp int64, nonce, jti []byte, body []byte) []byte {
	// Format: <method>\n<uri>\n<host>\n<timestamp>\n<nonce>\n<jti>[<body_digest>]
	canonical := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%s",
		method,
		uri,
		host,
		timestamp,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(jti))

	// Add body digest for methods with body
	if (method == "POST" || method == "PUT" || method == "PATCH") && len(body) > 0 {
		h := sha256.New()
		h.Write(body)
		digest := h.Sum(nil)
		canonical += "\n" + base64.RawURLEncoding.EncodeToString(digest)
	}

	return []byte(canonical)
}

// ValidateTimestamp checks if a timestamp is within acceptable bounds
// Updated to enforce ADR-002 60s limit with configurable minimum
func ValidateTimestamp(timestamp int64, maxSkew, minSkew time.Duration) error {
	// Enforce ADR-002 maximum
	if maxSkew > 60*time.Second {
		maxSkew = 60 * time.Second
	}

	// Apply minimum for high-assurance
	if minSkew > 0 && maxSkew > minSkew {
		maxSkew = minSkew
	}

	now := time.Now().Unix()
	diff := timestamp - now
	if diff < 0 {
		diff = -diff
	}

	if diff > int64(maxSkew.Seconds()) {
		return fmt.Errorf("timestamp outside acceptable window: diff=%ds, max=%ds", diff, int64(maxSkew.Seconds()))
	}

	return nil
}