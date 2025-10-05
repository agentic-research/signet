package header

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jamestexas/signet/pkg/crypto/keys"
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
	var err error

	// Zero sensitive fields on error
	defer func() {
		if err != nil && proof != nil {
			if proof.Nonce != nil {
				keys.ZeroizeBytes(proof.Nonce)
			}
			if proof.Signature != nil {
				keys.ZeroizeBytes(proof.Signature)
			}
		}
	}()

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
		err = fmt.Errorf("missing jti")
		return nil, err
	}
	if proof.Timestamp == 0 {
		err = fmt.Errorf("missing timestamp")
		return nil, err
	}
	if proof.Signature == nil {
		err = fmt.Errorf("missing signature")
		return nil, err
	}

	return proof, nil
}

// ParseSignetProofWithValidation parses and validates a Signet-Proof header with security checks
func ParseSignetProofWithValidation(header string, enforceMonotonic bool) (*SignetProof, error) {
	proof, err := ParseSignetProof(header)
	if err != nil {
		return nil, err
	}

	// Enforce monotonicity if requested
	if enforceMonotonic {
		if err := checkMonotonic(proof.JTI, proof.Timestamp); err != nil {
			return nil, err
		}
	}

	return proof, nil
}

// Package-level state for monotonicity enforcement
var lastTS sync.Map // map[string]int64  key: base64(jti)

// checkMonotonic ensures timestamps are strictly increasing for each JTI
// Simplified to avoid livelock under high contention
func checkMonotonic(jti []byte, ts int64) error {
	k := base64.RawURLEncoding.EncodeToString(jti)

	// Try to update atomically with a single CompareAndSwap
	actual, loaded := lastTS.LoadOrStore(k, ts)
	if !loaded {
		// New entry, we stored our timestamp
		return nil
	}

	// Entry exists, check if timestamp is strictly increasing
	existingTS := actual.(int64)
	if ts <= existingTS {
		return errors.New("timestamp not monotonic")
	}

	// Update to new timestamp - single attempt to avoid livelock
	// If this fails due to concurrent update, the other goroutine
	// will enforce monotonicity
	lastTS.CompareAndSwap(k, existingTS, ts)
	return nil
}

// ResetMonotonicCache clears the monotonicity cache - for testing only
func ResetMonotonicCache() {
	lastTS = sync.Map{}
}

// ValidateTimestamp validates that a timestamp falls within acceptable clock skew
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
