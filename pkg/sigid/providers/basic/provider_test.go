package basic

import (
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/signet"
)

func TestNewProvider(t *testing.T) {
	secret := []byte("test-secret")
	provider := NewProvider(secret)

	if provider == nil {
		t.Fatal("NewProvider returned nil")
	}

	if string(provider.issuerSecret) != string(secret) {
		t.Errorf("issuerSecret mismatch: got %v, want %v", provider.issuerSecret, secret)
	}
}

func TestExtractContext_NilToken(t *testing.T) {
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(nil)

	if err == nil {
		t.Fatal("expected error for nil token, got nil")
	}

	if ctx != nil {
		t.Errorf("expected nil context for nil token, got %v", ctx)
	}
}

func TestExtractContext_BasicToken(t *testing.T) {
	provider := NewProvider([]byte("test-secret"))

	// Create a minimal signet token
	token := &signet.Token{
		IssuerID:    "test-issuer",
		SubjectPPID: []byte("subject-ppid"),
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
		Actor: map[string]interface{}{
			"id": "actor-123",
		},
	}

	ctx, err := provider.ExtractContext(token)
	if err != nil {
		t.Fatalf("ExtractContext failed: %v", err)
	}

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}

	if ctx.Provenance == nil {
		t.Fatal("expected non-nil provenance")
	}

	if ctx.Provenance.Issuer != "test-issuer" {
		t.Errorf("issuer mismatch: got %v, want test-issuer", ctx.Provenance.Issuer)
	}

	if ctx.Provenance.ActorPPID == "" {
		t.Error("expected non-empty actor ppid")
	}

	if ctx.Environment == nil {
		t.Fatal("expected non-nil environment")
	}

	if ctx.Boundary == nil {
		t.Fatal("expected non-nil boundary")
	}
}

func TestExtractContext_WithDelegator(t *testing.T) {
	provider := NewProvider([]byte("test-secret"))

	token := &signet.Token{
		IssuerID:    "test-issuer",
		SubjectPPID: []byte("subject-ppid"),
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
		Actor: map[string]interface{}{
			"id": "actor-123",
		},
		Delegator: map[string]interface{}{
			"id": "delegator-456",
		},
	}

	ctx, err := provider.ExtractContext(token)
	if err != nil {
		t.Fatalf("ExtractContext failed: %v", err)
	}

	if ctx.Provenance.DelegatorPPID == "" {
		t.Error("expected non-empty delegator ppid")
	}

	if ctx.Provenance.ActorPPID == ctx.Provenance.DelegatorPPID {
		t.Error("actor ppid should differ from delegator ppid")
	}
}

func TestValidateContext_NilContext(t *testing.T) {
	provider := NewProvider(nil)
	err := provider.ValidateContext(nil, nil)

	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}
}

func TestValidateContext_StaleContext(t *testing.T) {
	provider := NewProvider(nil)

	token := &signet.Token{
		IssuerID:    "test-issuer",
		SubjectPPID: []byte("subject-ppid"),
		Actor: map[string]interface{}{
			"id": "actor-123",
		},
	}

	ctx, err := provider.ExtractContext(token)
	if err != nil {
		t.Fatalf("ExtractContext failed: %v", err)
	}

	// Make the context stale
	ctx.ExtractedAt = time.Now().Add(-10 * time.Minute)

	err = provider.ValidateContext(ctx, nil)
	if err == nil {
		t.Fatal("expected error for stale context, got nil")
	}
}

func TestDerivePPID_Deterministic(t *testing.T) {
	provider := NewProvider([]byte("test-secret"))

	ppid1 := provider.derivePPID("actor-123", "issuer-1")
	ppid2 := provider.derivePPID("actor-123", "issuer-1")

	if ppid1 != ppid2 {
		t.Error("ppid derivation should be deterministic")
	}
}

func TestDerivePPID_Different(t *testing.T) {
	provider := NewProvider([]byte("test-secret"))

	ppid1 := provider.derivePPID("actor-123", "issuer-1")
	ppid2 := provider.derivePPID("actor-456", "issuer-1")

	if ppid1 == ppid2 {
		t.Error("different actors should have different ppids")
	}
}

func TestDerivePPID_NoSecret(t *testing.T) {
	provider := NewProvider(nil)

	ppid1 := provider.derivePPID("actor-123", "issuer-1")
	ppid2 := provider.derivePPID("actor-123", "issuer-1")

	if ppid1 != ppid2 {
		t.Error("ppid derivation should be deterministic even without secret")
	}

	if ppid1 == "" {
		t.Error("ppid should not be empty")
	}
}
