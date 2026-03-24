package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCompiler_BasicFlow(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	c := NewCompiler(priv)

	// Define groups
	c.DefineGroup("developers", []uint64{0x0001, 0x0002}, 0)
	c.DefineGroup("contractors", []uint64{0x0001}, 7200)

	// Provision subjects
	c.AddSubject("github-123", []string{"developers"})
	c.AddSubject("github-456", []string{"developers", "contractors"})

	// Compile
	bundle, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Verify
	if err := bundle.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if bundle.Epoch != 1 {
		t.Errorf("Epoch = %d, want 1", bundle.Epoch)
	}
	if bundle.Seqno != 1 {
		t.Errorf("Seqno = %d, want 1", bundle.Seqno)
	}
	if len(bundle.Subjects) != 2 {
		t.Errorf("Subjects = %d, want 2", len(bundle.Subjects))
	}
	if len(bundle.Groups) != 2 {
		t.Errorf("Groups = %d, want 2", len(bundle.Groups))
	}

	// Check capabilities
	s := bundle.LookupSubject("github-456")
	caps := bundle.ResolveCapabilities(s)
	if len(caps) != 2 { // 0x0001 (from both groups, deduped) + 0x0002
		t.Errorf("caps = %v, want 2 capabilities", caps)
	}
}

func TestCompiler_SeqnoIncrementsMonotonically(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)
	c.AddSubject("user", []string{})

	b1, _ := c.Compile()
	b2, _ := c.Compile()
	b3, _ := c.Compile()

	if b1.Seqno >= b2.Seqno || b2.Seqno >= b3.Seqno {
		t.Errorf("seqno not monotonic: %d, %d, %d", b1.Seqno, b2.Seqno, b3.Seqno)
	}
}

func TestCompiler_RemoveSubjectBumpsEpoch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)

	c.AddSubject("fired-employee", []string{})
	b1, _ := c.Compile()

	c.RemoveSubject("fired-employee")
	b2, _ := c.Compile()

	if b2.Epoch <= b1.Epoch {
		t.Errorf("epoch should bump on RemoveSubject: %d <= %d", b2.Epoch, b1.Epoch)
	}
	if b2.LookupSubject("fired-employee") != nil {
		t.Error("removed subject should not be in bundle")
	}
}

func TestCompiler_DeactivateSubject(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)

	c.AddSubject("user", []string{"dev"})
	c.DeactivateSubject("user")

	bundle, _ := c.Compile()
	s := bundle.LookupSubject("user")
	if s == nil {
		t.Fatal("deactivated subject should still be in bundle")
	}
	if s.Active {
		t.Error("subject should be inactive")
	}
}

func TestCompiler_RemoveGroupNoEpochBump(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)

	c.DefineGroup("temp", []uint64{1}, 0)
	b1, _ := c.Compile()

	c.RemoveGroup("temp")
	b2, _ := c.Compile()

	if b2.Epoch != b1.Epoch {
		t.Errorf("removing group should NOT bump epoch: %d != %d", b2.Epoch, b1.Epoch)
	}
}

func TestCompiler_StagingIsolation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)

	c.AddSubject("user", []string{"dev"})
	bundle, _ := c.Compile()

	// Mutate staging after compile
	c.DeactivateSubject("user")

	// Bundle should not be affected
	s := bundle.LookupSubject("user")
	if !s.Active {
		t.Error("compiled bundle should be isolated from staging mutations")
	}
}

func TestCompiler_EndToEnd_WithChecker(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCompiler(priv)

	// Setup
	c.DefineGroup("employees", []uint64{0x0001, 0x0002}, 86400)
	c.AddSubject("github-james", []string{"employees"})
	c.AddSubject("github-bob", []string{"employees"})

	// Compile bundle
	bundle, err := c.Compile()
	if err != nil {
		t.Fatal(err)
	}

	// Create a fetcher that serves this bundle
	fetcher := &mockFetcher{bundle: bundle}
	checker := NewPolicyChecker(fetcher, pub, 0)

	// James should be allowed
	subject, err := checker.CheckSubject(t.Context(), "github-james")
	if err != nil {
		t.Fatalf("james should be allowed: %v", err)
	}
	caps, _ := checker.ResolveCapabilities(t.Context(), subject)
	if len(caps) != 2 {
		t.Errorf("james should have 2 caps, got %d", len(caps))
	}

	// Unknown user should be denied
	_, err = checker.CheckSubject(t.Context(), "github-attacker")
	if err == nil {
		t.Fatal("attacker should be denied")
	}

	// Deactivate bob, recompile
	c.DeactivateSubject("github-bob")
	bundle2, _ := c.Compile()
	fetcher.bundle = bundle2
	checker = NewPolicyChecker(fetcher, pub, 0) // fresh checker

	_, err = checker.CheckSubject(t.Context(), "github-bob")
	if err == nil {
		t.Fatal("deactivated bob should be denied")
	}
}
