package sigid

import (
	"testing"
	"time"
)

func TestContext_Creation(t *testing.T) {
	ctx := &Context{
		ExtractedAt: time.Now(),
		Provenance: &Provenance{
			ActorPPID: "test-actor-ppid",
			Issuer:    "test-issuer",
		},
		Environment: &Environment{
			ClusterID: "test-cluster",
		},
		Boundary: &Boundary{
			VPC: "test-vpc",
		},
	}

	if ctx.Provenance == nil {
		t.Fatal("expected non-nil provenance")
	}

	if ctx.Provenance.ActorPPID != "test-actor-ppid" {
		t.Errorf("actor ppid mismatch: got %v, want test-actor-ppid", ctx.Provenance.ActorPPID)
	}

	if ctx.Environment.ClusterID != "test-cluster" {
		t.Errorf("cluster id mismatch: got %v, want test-cluster", ctx.Environment.ClusterID)
	}

	if ctx.Boundary.VPC != "test-vpc" {
		t.Errorf("vpc mismatch: got %v, want test-vpc", ctx.Boundary.VPC)
	}
}

func TestAttestation_Creation(t *testing.T) {
	now := time.Now()
	att := &Attestation{
		Provider:  "SPIRE",
		Claims:    map[string]interface{}{"workload_id": "test-workload"},
		Signature: []byte("test-signature"),
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	if att.Provider != "SPIRE" {
		t.Errorf("provider mismatch: got %v, want SPIRE", att.Provider)
	}

	if len(att.Claims) != 1 {
		t.Errorf("claims count mismatch: got %d, want 1", len(att.Claims))
	}

	if att.ExpiresAt.Before(att.IssuedAt) {
		t.Error("expiry should be after issuance")
	}
}
