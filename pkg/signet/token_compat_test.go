package signet

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Golden wire vectors for the v0.0.1 → current layout boundary (signet-62f8e0).
//
// The historical v0.0.1 token used integer keys 1 issuer, 2 confirmation,
// 3 expiry, 4 nonce, 5 ephemeral key, 6 not-before. The current normative
// table (docs/design/001-signet-tokens.md) reassigned keys 2–6: confirmation
// moved to 9, nonce to 17, the ephemeral key to 18, and keys 2–6 now mean
// audience, subject PPID, expiry, not-before, issued-at. A v0.0.1 payload
// decoded field-by-field as a current token would therefore silently
// reinterpret bytes (e.g. legacy not-before at key 6 becomes issued-at).
// These vectors pin the deliberate behavior: such payloads are REJECTED with
// ErrLegacyTokenLayout, never decoded.
//
// The hex is canonical CBOR (CanonicalEncOptions) and must never change:
// these are wire-compat fixtures, not conveniences. Regenerating them with
// different content defeats their purpose.
const (
	// {1: "signet-issuer-v001", 2: 32×C0, 3: 1710000300, 4: 16×A0, 5: 32×E0, 6: 1710000000}
	goldenLegacyV001Hex = "a601727369676e65742d6973737565722d76303031025820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0031a65ec88ac0450a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0055820e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0061a65ec8780"

	// {1: "signet-issuer-current", 3: 32×5B, 4: 1710000300, 5: 1710000000,
	//  6: 1710000000, 7: 16×CA, 9: 32×CF, 13: 16×71}
	goldenCurrentHex = "a801757369676e65742d6973737565722d63757272656e740358205b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b041a65ec88ac051a65ec8780061a65ec87800750cacacacacacacacacacacacacacacaca095820cfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcf0d5071717171717171717171717171717171"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	return b
}

func TestGoldenLegacyV001PayloadRejected(t *testing.T) {
	_, err := Unmarshal(mustHex(t, goldenLegacyV001Hex))
	if err == nil {
		t.Fatal("v0.0.1 payload must not decode as a current token")
	}
	if !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("v0.0.1 payload must fail with ErrLegacyTokenLayout, got: %v", err)
	}
}

// The rejection must be the deliberate boundary error even when individual
// legacy fields would happen to type-check under the current schema (legacy
// key 6 not-before is an int, exactly what current key 6 issued-at expects).
func TestLegacyOverlappingKeysNotReinterpreted(t *testing.T) {
	// {1: "iss", 6: 1710000000} — a legacy-shaped fragment whose every field
	// is type-compatible with the current layout.
	fragment := "a20163697373061a65ec8780"
	_, err := Unmarshal(mustHex(t, fragment))
	if !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("type-compatible legacy fragment must hit the layout boundary, got: %v", err)
	}
}

func TestGoldenLegacyV001RejectedAtSIG1Layer(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(mustHex(t, goldenLegacyV001Hex))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-cose-sign1"))
	sig1 := strings.Join([]string{SIG1Prefix, payload, signature}, SIG1Separator)

	_, err := DecodeSIG1(sig1)
	if !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("SIG1 with v0.0.1 payload must surface ErrLegacyTokenLayout, got: %v", err)
	}
}

func TestGoldenCurrentPayloadDecodes(t *testing.T) {
	raw := mustHex(t, goldenCurrentHex)
	token, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("golden current payload must decode: %v", err)
	}
	if token.IssuerID != "signet-issuer-current" {
		t.Fatalf("issuer = %q", token.IssuerID)
	}
	if token.ExpiresAt != 1710000300 || token.NotBefore != 1710000000 || token.IssuedAt != 1710000000 {
		t.Fatalf("timestamps = exp %d nbf %d iat %d", token.ExpiresAt, token.NotBefore, token.IssuedAt)
	}
	if !bytes.Equal(token.ConfirmationID, bytes.Repeat([]byte{0xCF}, 32)) {
		t.Fatal("confirmation id mismatch")
	}

	// Canonical round-trip: re-encoding the decoded token must reproduce the
	// golden bytes exactly, or the wire format has drifted.
	reencoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, raw) {
		t.Fatalf("canonical re-encoding drifted from golden vector:\n got %x\nwant %x", reencoded, raw)
	}
}

// A payload missing every current-format required key (7 cap_id, 9 cnf,
// 13 jti) is indistinguishable from a legacy/unversioned token and must be
// stopped at the boundary, not decoded best-effort.
func TestCurrentShapeMissingAllRequiredKeysRejected(t *testing.T) {
	// {1: "iss", 4: 1710000300} — current-format semantics, but carries
	// none of the required keys.
	fragment := "a20163697373041a65ec88ac"
	_, err := Unmarshal(mustHex(t, fragment))
	if !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("payload without any required key must hit the layout boundary, got: %v", err)
	}
}

// Non-map payloads bypass the layout detector and fail in the ordinary
// struct decode with an ordinary error — the boundary must not misclassify.
func TestNonMapPayloadFailsStructDecodeNotBoundary(t *testing.T) {
	_, err := Unmarshal([]byte{0x83, 0x01, 0x02, 0x03}) // CBOR array [1,2,3]
	if err == nil {
		t.Fatal("array payload must not decode")
	}
	if errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("non-map payload must not be classified as legacy layout: %v", err)
	}
}
