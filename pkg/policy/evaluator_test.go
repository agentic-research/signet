package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestStaticPolicyEvaluator_AllowedRepo(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		AllowedRepositories: []string{"agentic-research/signet", "acme/app"},
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:agentic-research/signet:ref:refs/heads/main",
		Claims:   map[string]any{"repository": "agentic-research/signet"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}
}

func TestStaticPolicyEvaluator_DeniedRepo(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		AllowedRepositories: []string{"agentic-research/signet"},
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:evil/repo:ref:refs/heads/main",
		Claims:   map[string]any{"repository": "evil/repo"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied, got allowed")
	}
	if result.Reason == "" {
		t.Error("expected denial reason")
	}
}

func TestStaticPolicyEvaluator_AllowedWorkflow(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		AllowedWorkflows: []string{".github/workflows/release.yml"},
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:agentic-research/signet:ref:refs/heads/main",
		Claims: map[string]any{
			"repository": "agentic-research/signet",
			"workflow":   ".github/workflows/release.yml",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}
}

func TestStaticPolicyEvaluator_DeniedWorkflow(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		AllowedWorkflows: []string{".github/workflows/release.yml"},
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:agentic-research/signet:ref:refs/heads/main",
		Claims: map[string]any{
			"repository": "agentic-research/signet",
			"workflow":   ".github/workflows/hack.yml",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied, got allowed")
	}
	if result.Reason == "" {
		t.Error("expected denial reason")
	}
}

func TestStaticPolicyEvaluator_EmptyAllowlists(t *testing.T) {
	eval := &StaticPolicyEvaluator{}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:any/repo:ref:refs/heads/main",
		Claims:   map[string]any{"repository": "any/repo"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("empty allowlists should allow all, got denied: %s", result.Reason)
	}
}

func TestStaticPolicyEvaluator_CapabilityMapping(t *testing.T) {
	mapper := func(claims map[string]any) ([]string, error) {
		repo, _ := claims["repository"].(string)
		return []string{
			fmt.Sprintf("urn:signet:cap:write:repo:github.com/%s", repo),
			fmt.Sprintf("urn:signet:cap:read:repo:github.com/%s", repo),
		}, nil
	}
	eval := &StaticPolicyEvaluator{
		AllowedRepositories: []string{"agentic-research/signet"},
		MapCaps:             mapper,
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "repo:agentic-research/signet:ref:refs/heads/main",
		Claims:   map[string]any{"repository": "agentic-research/signet"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got denied: %s", result.Reason)
	}
	if len(result.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(result.Capabilities))
	}
	want := "urn:signet:cap:write:repo:github.com/agentic-research/signet"
	if result.Capabilities[0] != want {
		t.Errorf("capability[0] = %q, want %q", result.Capabilities[0], want)
	}
}

func TestStaticPolicyEvaluator_CapabilityMapperError(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		MapCaps: func(_ map[string]any) ([]string, error) {
			return nil, fmt.Errorf("mapper broken")
		},
	}
	_, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "test",
		Claims:   map[string]any{},
	})
	if err == nil {
		t.Error("expected error from broken mapper")
	}
}

func TestStaticPolicyEvaluator_ValidityOverride(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		DefaultValidity: 10 * time.Minute,
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "test",
		Claims:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Validity != 10*time.Minute {
		t.Errorf("validity = %v, want %v", result.Validity, 10*time.Minute)
	}
}

func TestStaticPolicyEvaluator_NilRequest(t *testing.T) {
	eval := &StaticPolicyEvaluator{}
	_, err := eval.Evaluate(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestStaticPolicyEvaluator_MissingRepoClaim(t *testing.T) {
	eval := &StaticPolicyEvaluator{
		AllowedRepositories: []string{"agentic-research/signet"},
	}
	result, err := eval.Evaluate(context.Background(), &EvaluationRequest{
		Provider: "github-actions",
		Subject:  "test",
		Claims:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied when repo claim is missing but allowlist is set")
	}
}
