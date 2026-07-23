package sigid

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

// fixedEd25519Pub returns the ADR-012 conformance-vector public key: the 32
// bytes 00,01,…,1f.
func fixedEd25519Pub() ed25519.PublicKey {
	pub := make(ed25519.PublicKey, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	return pub
}

// TestCanonicalKeyID_ADRVector is the Go leg of the cross-language contract:
// signet MUST reproduce the pinned ADR-012 vector byte-for-byte, exactly as
// notme's keyIdFromSpki does in workerd.
func TestCanonicalKeyID_ADRVector(t *testing.T) {
	kid, err := CanonicalKeyID(fixedEd25519Pub())
	if err != nil {
		t.Fatalf("CanonicalKeyID: %v", err)
	}
	const want = "9408457aefd071cec127c1f985399308"
	if kid != want {
		t.Fatalf("kid = %q, want ADR-012 vector %q", kid, want)
	}
}

// TestCanonicalKeyID_Shape pins the width + encoding: 128-bit, 32 lowercase hex.
func TestCanonicalKeyID_Shape(t *testing.T) {
	kid, err := CanonicalKeyID(fixedEd25519Pub())
	if err != nil {
		t.Fatalf("CanonicalKeyID: %v", err)
	}
	if len(kid) != 32 {
		t.Fatalf("kid length = %d, want 32 (128-bit)", len(kid))
	}
	for _, c := range kid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("kid %q contains a non-lowercase-hex char %q", kid, c)
		}
	}
	// The old 64-bit id is a leading prefix (migration is a widening, not a re-key).
	if kid[:16] != "9408457aefd071ce" {
		t.Fatalf("64-bit prefix = %q, want 9408457aefd071ce", kid[:16])
	}
}

// TestCanonicalKeyID_CanonicalizesEncoding is the NEGATIVE conformance vector
// (ADR-012 R2): the same key under a canonical (params ABSENT) and a
// non-canonical (params NULL) SPKI encoding MUST NOT yield two divergent kids.
// CanonicalKeyID takes a parsed key, so canonicalization happens at parse +
// re-marshal — this test drives both DER encodings through the parser and
// asserts they converge (or that the non-canonical form is rejected at parse,
// which is equally conformant: it never reaches a hash).
func TestCanonicalKeyID_CanonicalizesEncoding(t *testing.T) {
	pub := fixedEd25519Pub()
	keyHex := hex.EncodeToString(pub)

	canonicalDER, _ := hex.DecodeString("302a300506032b6570032100" + keyHex)     // params ABSENT (RFC 8410)
	nullParamDER, _ := hex.DecodeString("302c300706032b65700500032100" + keyHex) // params NULL (non-canonical)

	canonicalKey, err := x509.ParsePKIXPublicKey(canonicalDER)
	if err != nil {
		t.Fatalf("canonical SPKI must parse: %v", err)
	}
	canonicalKid, err := CanonicalKeyID(canonicalKey)
	if err != nil {
		t.Fatalf("CanonicalKeyID(canonical): %v", err)
	}

	nullKey, err := x509.ParsePKIXPublicKey(nullParamDER)
	if err != nil {
		// Rejecting the non-canonical encoding at parse is ADR-012-conformant —
		// it can never produce a divergent kid because it never parses.
		t.Logf("non-canonical NULL-params SPKI rejected at parse (%v) — conformant", err)
		return
	}
	nullKid, err := CanonicalKeyID(nullKey)
	if err != nil {
		t.Fatalf("CanonicalKeyID(null-params): %v", err)
	}
	// If it DID parse, canonicalize-then-hash must collapse it to the same kid.
	if nullKid != canonicalKid {
		t.Fatalf("canonicalization failed: null-params kid %q != canonical kid %q", nullKid, canonicalKid)
	}
}

// TestCanonicalKeyID_DistinctFromMachineFingerprint guards the deliberate
// non-conflation: the 128-bit kid is a prefix of, but not equal to, the
// full-width device fingerprint.
func TestCanonicalKeyID_DistinctFromMachineFingerprint(t *testing.T) {
	pub := fixedEd25519Pub()
	kid, err := CanonicalKeyID(pub)
	if err != nil {
		t.Fatalf("CanonicalKeyID: %v", err)
	}
	fp, err := MachineFingerprint(pub)
	if err != nil {
		t.Fatalf("MachineFingerprint: %v", err)
	}
	if kid == fp {
		t.Fatal("kid must not equal the full-width MachineFingerprint")
	}
	if len(fp) != 64 {
		t.Fatalf("MachineFingerprint length = %d, want 64 (256-bit)", len(fp))
	}
	if fp[:32] != kid {
		t.Fatalf("kid should be the leading 128 bits of the fingerprint: %q vs %q", kid, fp[:32])
	}
}
