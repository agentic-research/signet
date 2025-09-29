package header

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// SignetProof represents a parsed Signet-Proof header
type SignetProof struct {
	Version   string
	Mode      string
	Token     []byte
	JTI       []byte
	Cap       []byte
	Signature []byte
	Nonce     []byte
	Timestamp int64
}

// ParseSignetProof parses a Signet-Proof header value
// Format: v1;m=compact;t=<token>;jti=<jti>;cap=<cap>;s=<sig>;n=<nonce>;ts=<timestamp>
func ParseSignetProof(header string) (*SignetProof, error) {
	if header == "" {
		return nil, fmt.Errorf("empty header")
	}

	// Limit header size to prevent DoS
	if len(header) > 8192 {
		return nil, fmt.Errorf("header too large")
	}

	proof := &SignetProof{}
	parts := strings.Split(header, ";")
	seen := make(map[string]bool)

	for i, part := range parts {
		if i == 0 {
			// First part is version
			proof.Version = part
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid part: %s", part)
		}

		key := kv[0]
		value := kv[1]

		// Reject duplicate fields
		if seen[key] {
			return nil, fmt.Errorf("duplicate field: %s", key)
		}
		seen[key] = true

		switch key {
		case "m":
			proof.Mode = value
		case "t":
			// Limit token size
			if len(value) > 4096 {
				return nil, fmt.Errorf("token too large")
			}
			proof.Token = []byte(value) // Keep as string for simplicity in demo
		case "jti":
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid jti encoding: %w", err)
			}
			if len(decoded) != 16 {
				return nil, fmt.Errorf("jti must be 16 bytes")
			}
			proof.JTI = decoded
		case "cap":
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid cap encoding: %w", err)
			}
			proof.Cap = decoded
		case "s":
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid signature encoding: %w", err)
			}
			if len(decoded) < 64 {
				return nil, fmt.Errorf("signature too short")
			}
			proof.Signature = decoded
		case "n":
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid nonce encoding: %w", err)
			}
			if len(decoded) != 16 {
				return nil, fmt.Errorf("nonce must be 16 bytes")
			}
			proof.Nonce = decoded
		case "ts":
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp: %w", err)
			}
			proof.Timestamp = ts
		default:
			// Ignore unknown fields for forward compatibility
		}
	}

	// Validate required fields
	if proof.JTI == nil {
		return nil, fmt.Errorf("missing jti")
	}
	if proof.Timestamp == 0 {
		return nil, fmt.Errorf("missing timestamp")
	}
	if proof.Signature == nil {
		return nil, fmt.Errorf("missing signature")
	}

	return proof, nil
}