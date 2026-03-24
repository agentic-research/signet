package sigid

import (
	"context"
	"net/http"

	"github.com/agentic-research/signet/pkg/signet"
)

// ContextProvider extracts and validates identity context from signet tokens.
type ContextProvider interface {
	// ExtractContext extracts identity context from a verified signet token.
	// Returns an error if the token is malformed or context extraction fails.
	ExtractContext(token *signet.Token) (*Context, error)

	// ValidateContext validates the extracted context against the actual request context.
	// This allows checking that claimed boundaries match reality (e.g., claimed VPC matches actual source IP).
	ValidateContext(ctx *Context, request *http.Request) error
}

// AttestationProvider generates and verifies attestation claims.
type AttestationProvider interface {
	// Name returns the unique identifier for this attestation provider (e.g., "SPIRE", "TPM").
	Name() string

	// Attest generates a new attestation claim for the current runtime environment.
	Attest(ctx context.Context) (*Attestation, error)

	// Verify validates an attestation claim.
	Verify(attestation *Attestation) error
}

// BoundaryValidator validates boundary claims against actual request context.
type BoundaryValidator interface {
	// Validate checks that the claimed boundary matches the actual boundary.
	// claimed is from the token, actual is derived from the request.
	Validate(claimed *Boundary, actual *Boundary) error
}
