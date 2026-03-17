// Package policy provides authorization evaluation for OIDC subjects.
// It determines whether a subject is allowed to receive a bridge certificate
// and what capabilities they should get.
//
// See ADR-011 for design context: the authority needs a composable policy layer
// between OIDC token verification and certificate issuance.
package policy

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// PolicyEvaluator determines authorization for OIDC subjects.
type PolicyEvaluator interface {
	// Evaluate checks if a subject is allowed and returns granted capabilities.
	Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error)
}

// EvaluationRequest contains the information needed to evaluate a policy decision.
type EvaluationRequest struct {
	// Provider identifies the OIDC provider (e.g., "github-actions").
	Provider string

	// Subject is the OIDC sub claim.
	Subject string

	// Claims contains provider-specific claims (e.g., "repository", "workflow").
	Claims map[string]any

	// RequestedCaps lists capabilities the subject is requesting (optional).
	RequestedCaps []string
}

// EvaluationResult contains the policy decision.
type EvaluationResult struct {
	// Allowed indicates whether the subject is authorized.
	Allowed bool

	// Capabilities lists granted capability URIs.
	Capabilities []string

	// Validity overrides the default certificate validity (zero = use default).
	Validity time.Duration

	// Reason explains why the subject was denied (for logging, not for the subject).
	Reason string
}

// CapabilityMapper converts provider-specific claims into Signet capability URIs.
// This allows the policy evaluator to delegate capability mapping to provider-specific logic.
type CapabilityMapper func(claims map[string]any) ([]string, error)

// StaticPolicyEvaluator implements PolicyEvaluator using static allowlists.
// This wraps the existing AllowedRepositories/AllowedWorkflows config pattern
// from pkg/oidc/github.go into a composable interface.
type StaticPolicyEvaluator struct {
	// AllowedRepositories restricts which repositories can get bridge certificates.
	// Empty = allow all.
	AllowedRepositories []string

	// AllowedWorkflows restricts which workflow files can get bridge certificates.
	// Empty = allow all.
	AllowedWorkflows []string

	// DefaultValidity overrides cert validity when set (zero = use provider default).
	DefaultValidity time.Duration

	// MapCaps maps claims to capability URIs. If nil, no capabilities are granted.
	MapCaps CapabilityMapper
}

// Evaluate checks the subject against static allowlists and maps capabilities.
func (s *StaticPolicyEvaluator) Evaluate(_ context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	if req == nil {
		return nil, fmt.Errorf("evaluation request is nil")
	}
	// Use local claims reference to avoid mutating caller's request
	claims := req.Claims
	if claims == nil {
		claims = map[string]any{}
	}

	// Check repository allowlist
	if reason, ok := s.checkAllowlist(claims, "repository", s.AllowedRepositories); !ok {
		return &EvaluationResult{Allowed: false, Reason: reason}, nil
	}

	// Check workflow allowlist
	if reason, ok := s.checkAllowlist(claims, "workflow", s.AllowedWorkflows); !ok {
		return &EvaluationResult{Allowed: false, Reason: reason}, nil
	}

	// Map capabilities
	var caps []string
	if s.MapCaps != nil {
		var err error
		caps, err = s.MapCaps(claims)
		if err != nil {
			return nil, fmt.Errorf("capability mapping failed: %w", err)
		}
	}

	return &EvaluationResult{
		Allowed:      true,
		Capabilities: caps,
		Validity:     s.DefaultValidity,
	}, nil
}

// checkAllowlist checks if a claim value is in the allowlist.
// Returns ("", true) if allowed, (reason, false) if denied.
// Empty allowlist = allow all.
func (s *StaticPolicyEvaluator) checkAllowlist(
	claims map[string]any,
	claimKey string,
	allowlist []string,
) (string, bool) {
	if len(allowlist) == 0 {
		return "", true
	}

	val, ok := claims[claimKey].(string)
	if !ok || val == "" {
		return fmt.Sprintf("%s claim is missing or empty", claimKey), false
	}

	if !slices.Contains(allowlist, val) {
		return fmt.Sprintf("%s %q is not in allowed list", claimKey, val), false
	}

	return "", true
}
