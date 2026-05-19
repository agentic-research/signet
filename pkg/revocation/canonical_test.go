package revocation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/agentic-research/signet/pkg/revocation/types"
)

// TestBundleCanonical_NilBundle asserts that BundleCanonical refuses a nil
// bundle rather than panicking on the field accesses.
func TestBundleCanonical_NilBundle(t *testing.T) {
	if _, err := BundleCanonical(nil); err == nil {
		t.Fatal("BundleCanonical(nil) should error, got nil")
	}
}

// TestBundleCanonical_Deterministic asserts the function returns identical
// bytes for identical input. Underlying RFC 8949 §4.2 canonical CBOR is
// deterministic by construction; this test pins the property at the helper
// boundary so a future refactor can't silently break it.
func TestBundleCanonical_Deterministic(t *testing.T) {
	bundle := &types.CABundle{
		Epoch:     7,
		Seqno:     3,
		Keys:      map[string][]byte{"kid1": {0x01, 0x02, 0x03}, "kid2": {0x04, 0x05, 0x06}},
		KeyID:     "kid1",
		PrevKeyID: "",
		IssuedAt:  1_700_000_000,
		Signature: []byte("ignored"),
	}
	a, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic encoding: %x vs %x", a, b)
	}
}

// TestBundleCanonical_SignatureExcluded asserts that the Signature field is
// not part of the canonical bytes. Changing the signature must not change
// the verifier's input; otherwise verify would never succeed.
func TestBundleCanonical_SignatureExcluded(t *testing.T) {
	base := func() *types.CABundle {
		return &types.CABundle{
			Epoch:     1,
			Seqno:     1,
			Keys:      map[string][]byte{"kid": {0xab, 0xcd}},
			KeyID:     "kid",
			IssuedAt:  1234,
			Signature: []byte("first"),
		}
	}
	a, err := BundleCanonical(base())
	if err != nil {
		t.Fatal(err)
	}
	b2 := base()
	b2.Signature = []byte("different")
	b, err := BundleCanonical(b2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("Signature change altered canonical bytes: %x vs %x", a, b)
	}
}

// TestBundleCanonical_CrossRuntimeFixture pins the 25-byte canonical encoding
// for a fixed input. This fixture is shared with the TypeScript reference
// implementation in
// notme/worker/src/__tests__/bundle-canonical.test.ts ("matches a
// hand-computed CBOR fixture") — the byte sequences MUST be identical
// across both runtimes, otherwise cross-language CABundle verification is
// silently broken.
//
// Fixture inputs (mirrored byte-for-byte from notme's test):
//
//	epoch=1, seqno=1, keys={"kid": h'abcd'},
//	keyId="kid", prevKeyId="", issuedAt=1234, signature ignored.
//
// Expected RFC 8949 §4.2 canonical encoding (25 bytes):
//
//	a6                          map(6)
//	  01 01                     1 → 1
//	  02 01                     2 → 1
//	  03 a1 63 6b6964 42 abcd   3 → {"kid": h'abcd'}
//	  04 63 6b6964              4 → "kid"
//	  05 60                     5 → ""
//	  06 19 04d2                6 → 1234
//
// Drift: this fixture is the canary for a fxamacker/cbor upgrade that
// would change canonical-encoding behavior. If the bytes diverge here,
// any signed bundle in the wild produced by the old encoder will fail to
// verify under the new one. Pin the dependency or audit the diff before
// taking the upgrade.
func TestBundleCanonical_CrossRuntimeFixture(t *testing.T) {
	bundle := &types.CABundle{
		Epoch:     1,
		Seqno:     1,
		Keys:      map[string][]byte{"kid": {0xab, 0xcd}},
		KeyID:     "kid",
		PrevKeyID: "",
		IssuedAt:  1234,
		Signature: []byte("ignored — must not affect canonical bytes"),
	}
	got, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0xa6,
		0x01, 0x01,
		0x02, 0x01,
		0x03, 0xa1, 0x63, 0x6b, 0x69, 0x64, 0x42, 0xab, 0xcd,
		0x04, 0x63, 0x6b, 0x69, 0x64,
		0x05, 0x60,
		0x06, 0x19, 0x04, 0xd2,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-runtime fixture mismatch\n got: %s\nwant: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
	if len(got) != 25 {
		t.Fatalf("fixture should be exactly 25 bytes, got %d", len(got))
	}
}

// TestBundleCanonical_StringKeyOrderingCanonical pins RFC 8949 §4.2
// "shorter strings first; equal-length compared bytewise" ordering for
// string keys inside the Keys map. Mirrors notme's test of the same name
// ("sorts multi-key keys map per RFC 8949 §4.2 (length-then-bytewise, NOT
// alphabetical)"). The keys "b" and "ab" are chosen specifically because
// naive alphabetical sort would place "ab" before "b" (a < b), but
// canonical sort places "b" first (length 1 < length 2).
func TestBundleCanonical_StringKeyOrderingCanonical(t *testing.T) {
	bundle := &types.CABundle{
		Epoch: 1,
		Seqno: 1,
		Keys: map[string][]byte{
			"ab": {0x02},
			"b":  {0x01},
		},
		KeyID:     "b",
		PrevKeyID: "",
		IssuedAt:  1234,
	}
	got, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0xa6,
		0x01, 0x01,
		0x02, 0x01,
		0x03,
		0xa2,
		0x61, 0x62, // "b" — length 1, FIRST per §4.2
		0x41, 0x01, // h'01'
		0x62, 0x61, 0x62, // "ab" — length 2, SECOND
		0x41, 0x02, // h'02'
		0x04, 0x61, 0x62, // 4 → "b"
		0x05, 0x60, // 5 → ""
		0x06, 0x19, 0x04, 0xd2, // 6 → 1234
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("string-key ordering mismatch\n got: %s\nwant: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}
