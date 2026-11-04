package signet_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/agentic-research/signet/pkg/signet"
)

// IssuerKeyID reproduces the ADR-012 conformance vector (Ed25519 pubkey
// 00..1f), the value notme's keyIdFromSpki pins in its own tests.
func TestIssuerKeyID_ConformanceVector(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	got, err := signet.IssuerKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != "9408457aefd071cec127c1f985399308" {
		t.Fatalf("IssuerKeyID = %q, want %q", got, "9408457aefd071cec127c1f985399308")
	}
	kid, err := sigid.CanonicalKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	if kid != got {
		t.Fatalf("sigid.CanonicalKeyID = %q, IssuerKeyID = %q: the two must be one derivation", kid, got)
	}
}

func TestIssuerKeyID_RejectsUnusableKeys(t *testing.T) {
	if _, err := signet.IssuerKeyID(nil); err == nil {
		t.Fatal("nil key: want error")
	}
	if _, err := signet.IssuerKeyID("not a key"); err == nil {
		t.Fatal("non-key: want error")
	}
}

func newTestToken(t *testing.T, opts ...signet.TokenOption) (*signet.Token, error) {
	t.Helper()
	cnf := sha256.Sum256([]byte("master"))
	eph := sha256.Sum256([]byte("ephemeral"))
	return signet.NewToken("issuer", cnf[:], eph[:], nil, 5*time.Minute, opts...)
}

func TestNewToken_WithIssuerKey_SetsKeyIDAndRoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := signet.IssuerKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := newTestToken(t, signet.WithIssuerKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	if string(tok.KeyID) != want {
		t.Fatalf("KeyID = %q, want %q", tok.KeyID, want)
	}
	wire, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := signet.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(back.KeyID) != want {
		t.Fatalf("decoded KeyID = %q, want %q", back.KeyID, want)
	}
}

// A token minted without an issuer key (every token before this change) has
// no key 10 on the wire and still decodes, with an empty KeyID. The
// revocation checker then refuses it; that is intended.
func TestNewToken_WithoutIssuerKey_DecodesWithEmptyKeyID(t *testing.T) {
	tok, err := newTestToken(t)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := signet.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.KeyID) != 0 {
		t.Fatalf("KeyID = %q, want empty", back.KeyID)
	}
}

func TestNewToken_WithIssuerKey_BadKeyFails(t *testing.T) {
	if _, err := newTestToken(t, signet.WithIssuerKey(nil)); err == nil {
		t.Fatal("want error for a nil issuer key")
	}
}
