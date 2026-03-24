package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestTrustPolicyBundle_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bundle := &TrustPolicyBundle{
		Epoch:    1,
		Seqno:    42,
		IssuedAt: uint64(time.Now().Unix()),
		Subjects: map[string]*Subject{
			"github-12345": {
				Active: true,
				Groups: []string{"developers"},
			},
		},
		Groups: map[string]*Group{
			"developers": {
				CapTokens: []uint64{0x0001, 0x0002}, // read, write
			},
		},
	}

	if err := bundle.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(bundle.Signature) == 0 {
		t.Fatal("signature is empty after signing")
	}

	if err := bundle.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTrustPolicyBundle_VerifyRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	bundle := &TrustPolicyBundle{
		Epoch:    1,
		Seqno:    1,
		IssuedAt: uint64(time.Now().Unix()),
		Subjects: map[string]*Subject{
			"user-1": {Active: true, Groups: []string{"admin"}},
		},
		Groups: map[string]*Group{
			"admin": {CapTokens: []uint64{0xFFFF}},
		},
	}

	_ = bundle.Sign(priv)

	// Tamper: change epoch
	bundle.Epoch = 999
	if err := bundle.Verify(pub); err == nil {
		t.Fatal("expected verification to fail after tampering epoch")
	}
}

func TestTrustPolicyBundle_VerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	bundle := &TrustPolicyBundle{
		Epoch: 1, Seqno: 1, IssuedAt: uint64(time.Now().Unix()),
		Subjects: map[string]*Subject{},
		Groups:   map[string]*Group{},
	}
	_ = bundle.Sign(priv)

	if err := bundle.Verify(otherPub); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestTrustPolicyBundle_VerifyRejectsNoSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	bundle := &TrustPolicyBundle{Epoch: 1, Seqno: 1}

	if err := bundle.Verify(pub); err == nil {
		t.Fatal("expected error for unsigned bundle")
	}
}

func TestTrustPolicyBundle_LookupSubject(t *testing.T) {
	bundle := &TrustPolicyBundle{
		Subjects: map[string]*Subject{
			"github-12345": {Active: true, Groups: []string{"dev"}},
			"github-99999": {Active: false, Groups: []string{"dev"}},
		},
	}

	// Found and active
	s := bundle.LookupSubject("github-12345")
	if s == nil || !s.Active {
		t.Error("expected active subject github-12345")
	}

	// Found but deactivated
	s = bundle.LookupSubject("github-99999")
	if s == nil || s.Active {
		t.Error("expected inactive subject github-99999")
	}

	// Not found
	s = bundle.LookupSubject("unknown")
	if s != nil {
		t.Error("expected nil for unknown subject")
	}
}

func TestTrustPolicyBundle_ResolveCapabilities(t *testing.T) {
	bundle := &TrustPolicyBundle{
		Groups: map[string]*Group{
			"readers":     {CapTokens: []uint64{0x0001}},
			"writers":     {CapTokens: []uint64{0x0002}},
			"admin":       {CapTokens: []uint64{0x0001, 0x0002, 0x0003}},
			"nonexistent": {},
		},
	}

	// Subject in multiple groups — capabilities merged, deduplicated
	subject := &Subject{Active: true, Groups: []string{"readers", "writers", "admin"}}
	caps := bundle.ResolveCapabilities(subject)
	if len(caps) != 3 {
		t.Errorf("expected 3 capabilities, got %d: %v", len(caps), caps)
	}

	// Subject with no groups
	subject = &Subject{Active: true, Groups: nil}
	caps = bundle.ResolveCapabilities(subject)
	if len(caps) != 0 {
		t.Errorf("expected 0 capabilities for no groups, got %d", len(caps))
	}

	// Nil subject
	caps = bundle.ResolveCapabilities(nil)
	if caps != nil {
		t.Error("expected nil for nil subject")
	}
}

func TestTrustPolicyBundle_ResolveMaxCertTTL(t *testing.T) {
	bundle := &TrustPolicyBundle{
		Groups: map[string]*Group{
			"employees":   {CapTokens: []uint64{1}, MaxCertTTL: 86400}, // 24h
			"contractors": {CapTokens: []uint64{1}, MaxCertTTL: 7200},  // 2h
		},
	}

	// Subject-level override takes precedence
	subject := &Subject{Active: true, Groups: []string{"employees"}, MaxCertTTL: 3600}
	ttl := bundle.ResolveMaxCertTTL(subject)
	if ttl != 3600 {
		t.Errorf("expected subject override 3600, got %d", ttl)
	}

	// No subject override — use most restrictive group
	subject = &Subject{Active: true, Groups: []string{"employees", "contractors"}}
	ttl = bundle.ResolveMaxCertTTL(subject)
	if ttl != 7200 {
		t.Errorf("expected most restrictive group 7200, got %d", ttl)
	}

	// No overrides anywhere
	subject = &Subject{Active: true, Groups: []string{}}
	ttl = bundle.ResolveMaxCertTTL(subject)
	if ttl != 0 {
		t.Errorf("expected 0 (system default), got %d", ttl)
	}
}

func TestTrustPolicyBundle_MarshalRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	original := &TrustPolicyBundle{
		Epoch:    3,
		Seqno:    17,
		IssuedAt: uint64(time.Now().Unix()),
		Subjects: map[string]*Subject{
			"user-a": {Active: true, Groups: []string{"dev", "ops"}, Algorithm: "Ed25519"},
			"user-b": {Active: false, Groups: []string{"dev"}},
		},
		Groups: map[string]*Group{
			"dev": {CapTokens: []uint64{1, 2}},
			"ops": {CapTokens: []uint64{1, 3}, MaxCertTTL: 3600},
		},
	}
	_ = original.Sign(priv)

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	restored, err := UnmarshalBundle(data)
	if err != nil {
		t.Fatalf("UnmarshalBundle: %v", err)
	}

	if restored.Epoch != original.Epoch {
		t.Errorf("Epoch: got %d, want %d", restored.Epoch, original.Epoch)
	}
	if restored.Seqno != original.Seqno {
		t.Errorf("Seqno: got %d, want %d", restored.Seqno, original.Seqno)
	}
	if len(restored.Subjects) != 2 {
		t.Errorf("Subjects count: got %d, want 2", len(restored.Subjects))
	}
	if len(restored.Groups) != 2 {
		t.Errorf("Groups count: got %d, want 2", len(restored.Groups))
	}
	if len(restored.Signature) == 0 {
		t.Error("Signature lost in round-trip")
	}
}

func TestTrustPolicyBundle_DomainSeparation(t *testing.T) {
	// Verify that bundles signed with domain prefix cannot be verified
	// by anything that doesn't use the same prefix
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	bundle := &TrustPolicyBundle{
		Epoch: 1, Seqno: 1, IssuedAt: uint64(time.Now().Unix()),
		Subjects: map[string]*Subject{},
		Groups:   map[string]*Group{},
	}
	_ = bundle.Sign(priv)

	// Normal verify should work
	if err := bundle.Verify(pub); err != nil {
		t.Fatalf("normal verify failed: %v", err)
	}

	// Raw ed25519.Verify without domain prefix should fail
	payload, _ := cbor.CanonicalEncOptions().EncMode()
	enc, _ := payload.Marshal(map[int]any{
		1: bundle.Epoch, 2: bundle.Seqno,
		3: bundle.Subjects, 4: bundle.Groups, 5: bundle.IssuedAt,
	})
	// Verify without prefix — should NOT match
	if ed25519.Verify(pub, enc, bundle.Signature) {
		t.Error("signature should NOT verify without domain separation prefix")
	}
}
