// Package basic provides a reference implementation of the sigid ContextProvider.
package basic

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/agentic-research/signet/pkg/signet"
)

// Provider is a basic implementation of ContextProvider that extracts
// identity context from signet tokens.
type Provider struct {
	// IssuerSecret is used for ppid derivation (HMAC-SHA256)
	// In production, this should come from secure key management
	issuerSecret []byte
}

// NewProvider creates a new basic ContextProvider.
// If issuerSecret is nil, ppids will be derived from cleartext identities (less secure).
func NewProvider(issuerSecret []byte) *Provider {
	return &Provider{
		issuerSecret: issuerSecret,
	}
}

// ExtractContext extracts identity context from a verified signet token.
func (p *Provider) ExtractContext(token *signet.Token) (*sigid.Context, error) {
	if token == nil {
		return nil, fmt.Errorf("extract context: token is nil")
	}

	ctx := &sigid.Context{
		ExtractedAt: time.Now(),
	}

	// Extract provenance (with ppid derivation)
	prov, err := p.extractProvenance(token)
	if err != nil {
		return nil, fmt.Errorf("extract provenance: %w", err)
	}
	ctx.Provenance = prov

	// Extract environment (attestations, cluster info)
	env := p.extractEnvironment(token)
	ctx.Environment = env

	// Extract boundary (scope constraints)
	boundary := p.extractBoundary(token)
	ctx.Boundary = boundary

	return ctx, nil
}

// ValidateContext validates the extracted context against the actual request context.
func (p *Provider) ValidateContext(ctx *sigid.Context, request *http.Request) error {
	if ctx == nil {
		return fmt.Errorf("validate context: context is nil")
	}

	// Basic validation: check that context was extracted recently
	if time.Since(ctx.ExtractedAt) > 5*time.Minute {
		return fmt.Errorf("validate context: context is stale (extracted %v ago)", time.Since(ctx.ExtractedAt))
	}

	// Future: Add boundary validation (VPC, region matching)
	// Future: Add environment validation (cluster ID matching)

	return nil
}

// extractProvenance extracts provenance information from the token.
// Falls back to legacy Actor/Delegator fields if sigid fields (20-23) are absent.
func (p *Provider) extractProvenance(token *signet.Token) (*sigid.Provenance, error) {
	prov := &sigid.Provenance{
		Issuer: token.IssuerID,
	}

	// Extract actor identity
	// For now, use legacy Actor field (field 14)
	// TODO: Add support for field 20 (sigid Provenance)
	if token.Actor != nil {
		if actorID, ok := token.Actor["id"].(string); ok {
			// Derive ppid from cleartext identity
			prov.ActorPPID = p.derivePPID(actorID, token.IssuerID)
		} else {
			return nil, fmt.Errorf("extract provenance: actor.id is not a string")
		}
	} else {
		// No actor field - use subject ppid as fallback
		prov.ActorPPID = hex.EncodeToString(token.SubjectPPID)
	}

	// Extract delegator identity (if present)
	if token.Delegator != nil {
		if delegatorID, ok := token.Delegator["id"].(string); ok {
			prov.DelegatorPPID = p.derivePPID(delegatorID, token.IssuerID)
		}
	}

	return prov, nil
}

// extractEnvironment extracts environment attestations from the token.
func (p *Provider) extractEnvironment(token *signet.Token) *sigid.Environment {
	env := &sigid.Environment{
		Attestations: []sigid.Attestation{},
	}

	// TODO: Extract from field 21 (sigid Environment)
	// TODO: Extract cluster ID, image digest

	return env
}

// extractBoundary extracts boundary constraints from the token.
func (p *Provider) extractBoundary(token *signet.Token) *sigid.Boundary {
	boundary := &sigid.Boundary{}

	// TODO: Extract from field 22 (sigid Boundary)
	// TODO: Extract VPC, region, domain

	return boundary
}

// derivePPID derives a pairwise pseudonymous identifier from a cleartext identity.
// Uses HMAC-SHA256(issuerSecret, issuer+":"+identity) for privacy-preserving ppids.
// The issuer is included in the HMAC input so the same identity produces different
// ppids across different issuers (unlinkability).
func (p *Provider) derivePPID(identity, issuer string) string {
	if len(p.issuerSecret) == 0 {
		// Fallback: SHA-256 hash (deterministic but linkable across services)
		hash := sha256.Sum256([]byte(issuer + ":" + identity))
		return hex.EncodeToString(hash[:])
	}

	// HMAC-SHA256 for unlinkable ppids (matches cell provider pattern)
	mac := hmac.New(sha256.New, p.issuerSecret)
	mac.Write([]byte(issuer + ":" + identity))
	return hex.EncodeToString(mac.Sum(nil))
}
