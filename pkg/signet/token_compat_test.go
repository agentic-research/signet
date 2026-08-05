package signet

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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

// The minimal payload from the adversarial review that originally defeated
// this boundary, pinned verbatim: {1: "iss", 6: 1710000000, "x": 0}.
//
// It is sharper than the full-legacy-payload evasion cases above. Every
// integer field in it is type-compatible with the CURRENT schema (key 6 is
// an int in both layouts), so when the probe failed open on the text key,
// the struct decode succeeded outright — populating IssuerID and IssuedAt
// from legacy fields with no error at all. Only `validate()` stopped it,
// which is the incidental backstop this boundary exists to not depend on.
// If this test ever fails, the boundary has regressed to fail-open.
func TestReportedMinimalFailOpenRepro(t *testing.T) {
	const repro = "a30163697373061a65ec8780617800"
	tok, err := Unmarshal(mustHex(t, repro))
	if err == nil {
		t.Fatalf("fail-open regression: reproducer decoded into a token: %+v", tok)
	}
	if !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("reproducer must fail at the layout boundary, not incidentally: %v", err)
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

// Evasion attempts against the boundary. Each builds a payload whose legacy
// fields would reach field-by-field decoding if the detector could be
// bypassed by key SHAPE rather than key VALUES. An earlier revision probed
// with map[int64]cbor.RawMessage, which failed outright on any non-integer
// key and let all of these through to whatever incidental type mismatch the
// struct decode happened to produce.
func TestLegacyLayoutEvasionAttempts(t *testing.T) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	legacyFields := func() map[any]any {
		return map[any]any{
			int64(1): "signet-issuer-v001",
			int64(2): bytes.Repeat([]byte{0xC0}, 32),
			int64(3): int64(1710000300),
			int64(4): bytes.Repeat([]byte{0xA0}, 16),
			int64(5): bytes.Repeat([]byte{0xE0}, 32),
			int64(6): int64(1710000000),
		}
	}

	// The decoder's full key domain, minus the encodings Go cannot express as
	// map keys — those are hand-assembled in the tests below. Exhaustive over
	// an enumerable domain beats sampling it.
	cases := []struct {
		name      string
		poisonKey any
	}{
		{"text key", "x"},
		{"negative int key", int64(-1)},
		{"bool key", true},
		{"float key", 1.5},
		{"nil key", nil},
		{"simple value key", cbor.SimpleValue(200)},
		{"time key", time.Unix(1710000000, 0)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := legacyFields()
			payload[tc.poisonKey] = 0
			raw, err := enc.Marshal(payload)
			if err != nil {
				t.Skipf("encoder rejects this key shape (%v): not a reachable payload", err)
			}
			if _, err := Unmarshal(raw); !errors.Is(err, ErrLegacyTokenLayout) {
				t.Fatalf("legacy payload + %s must hit the layout boundary, got: %v", tc.name, err)
			}
		})
	}
}

// A byte-string map key has no Go map-key representation, so this payload is
// hand-assembled rather than built from a Go map: the golden legacy map (a6,
// six pairs) widened to seven (a7) with a bstr key appended. Whatever the
// decoder maps that key to, it is not an integer key, so the boundary must
// reject — pinned here so a decoder-behavior change cannot silently open a
// path to field decoding.
func TestByteStringMapKeyNeverYieldsToken(t *testing.T) {
	widened := "a7" + goldenLegacyV001Hex[2:] + "410100" // + {h'01': 0}
	tok, err := Unmarshal(mustHex(t, widened))
	if err == nil {
		t.Fatalf("payload with byte-string key decoded into a token: %+v", tok)
	}
	t.Logf("rejected with: %v", err)
}

// Key encodings whose decoded Go value is UNHASHABLE (CBOR array, map, and
// negative bignum) make the probe decode itself fail. An earlier revision
// passed those through to the struct decode on the assumption that a probe
// failure meant "not a map" — reopening the very bypass the boundary closes.
// Map-ness is now decided from the CBOR head byte, so these reject.
func TestUnhashableKeyEncodingsRejected(t *testing.T) {
	cases := []struct {
		name   string
		keyHex string // CBOR encoding of the key, value 0x00 appended
	}{
		{"array key", "80"},
		{"map key", "a0"},
		{"negative bignum key", "c349010000000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			widened := "a7" + goldenLegacyV001Hex[2:] + tc.keyHex + "00"
			if _, err := Unmarshal(mustHex(t, widened)); !errors.Is(err, ErrLegacyTokenLayout) {
				t.Fatalf("legacy payload + %s must hit the layout boundary, got: %v", tc.name, err)
			}
		})
	}
}

// Duplicate map keys must be rejected, not tie-broken. With the library
// default the generic map decode keeps the LAST occurrence and the struct
// decode keeps the FIRST, so a duplicated key could let the layout probe
// inspect one value while the token binds another.
func TestDuplicateMapKeysRejected(t *testing.T) {
	// Golden current payload (8 pairs, a8) widened to 9 (a9) with key 1
	// repeated carrying a different issuer.
	widened := "a9" + goldenCurrentHex[2:] + "0163646966" // + {1: "dif"}
	tok, err := Unmarshal(mustHex(t, widened))
	if err == nil {
		t.Fatalf("duplicate map key must be rejected, got token: %+v", tok)
	}
	if errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("duplicate key must fail as a decode error, not be misclassified as legacy layout: %v", err)
	}
	t.Logf("rejected with: %v", err)
}

// A key beyond int64 range cannot name a token field; treat it as a
// non-integer key rather than wrapping it into a valid-looking one.
func TestOutOfRangeIntegerKeyRejected(t *testing.T) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	raw, err := enc.Marshal(map[any]any{uint64(math.MaxUint64): 0, int64(1): "iss"})
	if err != nil {
		t.Skipf("encoder rejects out-of-range key: %v", err)
	}
	if _, err := Unmarshal(raw); !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("out-of-range integer key must hit the layout boundary, got: %v", err)
	}
}

// A current-format token carrying an extra non-integer key is also rejected:
// the schema is integer-keyed exclusively, so this is malformed regardless of
// whether the required keys are present.
func TestCurrentPayloadWithNonIntegerKeyRejected(t *testing.T) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	raw, err := enc.Marshal(map[any]any{
		int64(1):  "signet-issuer-current",
		int64(3):  bytes.Repeat([]byte{0x5B}, 32),
		int64(4):  int64(1710000300),
		int64(5):  int64(1710000000),
		int64(6):  int64(1710000000),
		int64(7):  bytes.Repeat([]byte{0xCA}, 16),
		int64(9):  bytes.Repeat([]byte{0xCF}, 32),
		int64(13): bytes.Repeat([]byte{0x71}, 16),
		"extra":   1,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Unmarshal(raw); !errors.Is(err, ErrLegacyTokenLayout) {
		t.Fatalf("non-integer key must be rejected even alongside required keys, got: %v", err)
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
