// Package cell provides a hierarchical IAM implementation using SignetAuthCell chains.
package cell

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/fxamacker/cbor/v2"
)

// CellProvider implements ContextProvider by evaluating chains of SignetAuthCell structures.
type CellProvider struct {
	// issuerSecret is used for HMAC-SHA256 PPID derivation
	// This ensures PPIDs are deterministic but unlinkable across different issuers
	issuerSecret []byte
}

// NewProvider creates a new CellProvider.
// If issuerSecret is provided, PPIDs will be derived using HMAC-SHA256 for unlinkability.
// If issuerSecret is nil, PPIDs will use simple SHA256 (less secure, for testing only).
func NewProvider(issuerSecret []byte) *CellProvider {
	return &CellProvider{
		issuerSecret: issuerSecret,
	}
}

// ExtractContext extracts identity context from a signet token containing SignetAuthCell chains.
func (p *CellProvider) ExtractContext(token *signet.Token) (*sigid.Context, error) {
	if token == nil {
		return nil, fmt.Errorf("extract context: token is nil")
	}

	// Try to extract chain from legacy Actor field (for backward compatibility with tests)
	chain, err := p.extractChainLegacy(token)
	if err != nil {
		return nil, fmt.Errorf("extract chain: %w", err)
	}

	return p.extractContextFromChain(chain)
}

// ExtractContextFromCBOR extracts identity context from a CBOR-encoded token with sigid fields.
// This is the primary method for production use, as it properly reads sigid fields 20-22.
func (p *CellProvider) ExtractContextFromCBOR(tokenCBOR []byte) (*sigid.Context, error) {
	if len(tokenCBOR) == 0 {
		return nil, fmt.Errorf("extract context: token CBOR is empty")
	}

	// Unmarshal token to map to access all sigid fields
	var tokenMap map[int]interface{}
	if err := cbor.Unmarshal(tokenCBOR, &tokenMap); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}

	// Extract chain from field 20
	chain, err := p.extractChainFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("extract chain: %w", err)
	}

	// Extract environment from field 21 (optional)
	environment, err := p.extractEnvironmentFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("extract environment: %w", err)
	}

	// Extract boundary from field 22 (optional)
	boundary, err := p.extractBoundaryFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("extract boundary: %w", err)
	}

	return p.buildContext(chain, environment, boundary)
}

// extractContextFromChain is the common logic for extracting context from a verified chain.
// This is used by the legacy ExtractContext method.
func (p *CellProvider) extractContextFromChain(chain []sigid.SignetAuthCell) (*sigid.Context, error) {
	return p.buildContext(chain, nil, nil)
}

// buildContext creates a Context from verified chain, environment, and boundary claims.
func (p *CellProvider) buildContext(chain []sigid.SignetAuthCell, environment *sigid.Environment, boundary *sigid.Boundary) (*sigid.Context, error) {
	// Verify the chain signatures
	if err := p.verifyChain(chain); err != nil {
		return nil, fmt.Errorf("verify chain: %w", err)
	}

	// Extract provenance from the final cell in the chain
	provenance := p.extractProvenance(chain)

	// Use provided environment or create empty one
	if environment == nil {
		environment = &sigid.Environment{}
	}

	// Use provided boundary or create empty one
	if boundary == nil {
		boundary = &sigid.Boundary{}
	}

	// Build context
	ctx := &sigid.Context{
		Provenance:  provenance,
		Environment: environment,
		Boundary:    boundary,
		ExtractedAt: time.Now(),
	}

	return ctx, nil
}

// extractChainFromMap extracts the SignetAuthCell chain from a token CBOR map (field 20).
func (p *CellProvider) extractChainFromMap(tokenMap map[int]interface{}) ([]sigid.SignetAuthCell, error) {
	chainField, ok := tokenMap[sigid.FieldProvenance]
	if !ok {
		return nil, fmt.Errorf("field %d (provenance chain) not present in token", sigid.FieldProvenance)
	}

	chainCBOR, ok := chainField.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d is not a byte array", sigid.FieldProvenance)
	}

	var chain []sigid.SignetAuthCell
	if err := cbor.Unmarshal(chainCBOR, &chain); err != nil {
		return nil, fmt.Errorf("unmarshal chain: %w", err)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("chain is empty")
	}

	return chain, nil
}

// extractEnvironmentFromMap extracts environment claims from a token CBOR map (field 21).
// Returns nil if field 21 is not present (environment claims are optional).
func (p *CellProvider) extractEnvironmentFromMap(tokenMap map[int]interface{}) (*sigid.Environment, error) {
	envField, ok := tokenMap[sigid.FieldEnvironment]
	if !ok {
		return nil, nil // Environment is optional
	}

	envCBOR, ok := envField.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d (environment) is not a byte array", sigid.FieldEnvironment)
	}

	var environment sigid.Environment
	if err := cbor.Unmarshal(envCBOR, &environment); err != nil {
		return nil, fmt.Errorf("unmarshal environment: %w", err)
	}

	return &environment, nil
}

// extractBoundaryFromMap extracts boundary claims from a token CBOR map (field 22).
// Returns nil if field 22 is not present (boundary claims are optional).
func (p *CellProvider) extractBoundaryFromMap(tokenMap map[int]interface{}) (*sigid.Boundary, error) {
	boundaryField, ok := tokenMap[sigid.FieldBoundary]
	if !ok {
		return nil, nil // Boundary is optional
	}

	boundaryCBOR, ok := boundaryField.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d (boundary) is not a byte array", sigid.FieldBoundary)
	}

	var boundary sigid.Boundary
	if err := cbor.Unmarshal(boundaryCBOR, &boundary); err != nil {
		return nil, fmt.Errorf("unmarshal boundary: %w", err)
	}

	return &boundary, nil
}

// extractChainLegacy extracts the SignetAuthCell chain from the token's Actor field.
// This is for backward compatibility with existing tests. New code should use
// ExtractContextFromCBOR which reads from CBOR field 20.
func (p *CellProvider) extractChainLegacy(token *signet.Token) ([]sigid.SignetAuthCell, error) {
	if token.Actor == nil {
		return nil, fmt.Errorf("no actor field in token")
	}

	chainCBOR, ok := token.Actor["chain"].([]byte)
	if !ok {
		return nil, fmt.Errorf("actor.chain is not a byte array")
	}

	var chain []sigid.SignetAuthCell
	if err := cbor.Unmarshal(chainCBOR, &chain); err != nil {
		return nil, fmt.Errorf("unmarshal chain: %w", err)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("chain is empty")
	}

	return chain, nil
}

// verifyChain verifies all signatures in the cell chain
// For a valid chain:
// 1. The first cell must be self-signed (signed by its own owner)
// 2. Each subsequent cell must be signed by the owner of the previous cell
func (p *CellProvider) verifyChain(chain []sigid.SignetAuthCell) error {
	if len(chain) == 0 {
		return fmt.Errorf("chain is empty")
	}

	for i, cell := range chain {
		// Determine who should have signed this cell
		var signerPubKey []byte
		if i == 0 {
			// First cell: self-signed by its owner
			signerPubKey = cell.Owner
		} else {
			// Subsequent cells: signed by previous cell's owner
			signerPubKey = chain[i-1].Owner
		}

		// Verify the signature
		if err := p.verifyCell(&cell, signerPubKey); err != nil {
			return fmt.Errorf("verify cell %d: %w", i, err)
		}
	}

	return nil
}

// verifyCell verifies a single cell's signature
func (p *CellProvider) verifyCell(cell *sigid.SignetAuthCell, signerPubKey []byte) error {
	if len(signerPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(signerPubKey))
	}

	if len(cell.Signature) == 0 {
		return fmt.Errorf("cell has no signature")
	}

	// Clone the cell and zero out signature for verification
	cellForVerification := *cell
	cellForVerification.Signature = []byte{}

	// Marshal to canonical CBOR
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("create CBOR encoder: %w", err)
	}
	data, err := encMode.Marshal(&cellForVerification)
	if err != nil {
		return fmt.Errorf("marshal cell: %w", err)
	}

	// Verify Ed25519 signature
	pubKey := ed25519.PublicKey(signerPubKey)
	if !ed25519.Verify(pubKey, data, cell.Signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// extractProvenance extracts provenance information from the cell chain
// The actor PPID is derived from the owner of the final cell using HMAC-SHA256
func (p *CellProvider) extractProvenance(chain []sigid.SignetAuthCell) *sigid.Provenance {
	if len(chain) == 0 {
		return &sigid.Provenance{}
	}

	finalCell := chain[len(chain)-1]

	// Derive PPID from owner public key
	ppid := p.derivePPID(finalCell.Owner)

	// Build chain of PPIDs for delegation tracking
	ppidChain := make([]string, len(chain))
	for i, cell := range chain {
		ppidChain[i] = p.derivePPID(cell.Owner)
	}

	// Delegator is the owner of the penultimate cell (if chain length > 1)
	var delegatorPPID string
	if len(chain) > 1 {
		delegatorPPID = p.derivePPID(chain[len(chain)-2].Owner)
	}

	return &sigid.Provenance{
		ActorPPID:     ppid,
		DelegatorPPID: delegatorPPID,
		Chain:         ppidChain,
		Issuer:        finalCell.Resource, // Using resource as issuer for now
	}
}

// derivePPID derives a pairwise pseudonymous identifier from a public key.
// Uses HMAC-SHA256 with the issuer secret for privacy-preserving, unlinkable PPIDs.
// Falls back to SHA256 if no issuer secret is configured (testing only).
func (p *CellProvider) derivePPID(publicKey []byte) string {
	if len(p.issuerSecret) == 0 {
		// Fallback: simple hash (less secure, for testing only)
		hash := sha256.Sum256(publicKey)
		return hex.EncodeToString(hash[:])
	}

	// HMAC-SHA256 for unlinkable PPIDs
	mac := hmac.New(sha256.New, p.issuerSecret)
	mac.Write(publicKey)
	ppid := mac.Sum(nil)
	return hex.EncodeToString(ppid)
}

// ValidateContext validates the extracted context against the actual request context.
// This checks that claimed boundaries match reality and the context is not stale.
func (p *CellProvider) ValidateContext(ctx *sigid.Context, request *http.Request) error {
	if ctx == nil {
		return fmt.Errorf("validate context: context is nil")
	}

	// Check that context is not stale (extracted within last 5 minutes)
	if time.Since(ctx.ExtractedAt) > 5*time.Minute {
		return fmt.Errorf("validate context: context is stale (extracted %v ago)", time.Since(ctx.ExtractedAt))
	}

	// Validate boundary claims if present
	if ctx.Boundary != nil {
		if err := p.validateBoundary(ctx.Boundary, request); err != nil {
			return fmt.Errorf("validate boundary: %w", err)
		}
	}

	return nil
}

// validateBoundary validates boundary claims against the actual request.
// This validates domain boundaries and VPC CIDR blocks.
func (p *CellProvider) validateBoundary(boundary *sigid.Boundary, request *http.Request) error {
	if request == nil {
		return nil // No request to validate against
	}

	// Validate domain boundary (if specified)
	if boundary.Domain != "" {
		actualDomain := request.Host
		if actualDomain != boundary.Domain {
			return fmt.Errorf("domain mismatch: claimed %s, actual %s", boundary.Domain, actualDomain)
		}
	}

	// Validate VPC CIDR boundary (if specified)
	if boundary.VPC != "" {
		if err := p.validateVPCBoundary(boundary.VPC, request.RemoteAddr); err != nil {
			return fmt.Errorf("VPC boundary validation failed: %w", err)
		}
	}

	// Future: Validate Region boundary (would require cloud provider metadata)

	return nil
}

// validateVPCBoundary checks if the request's IP address is within the specified CIDR block.
func (p *CellProvider) validateVPCBoundary(vpcCIDR string, remoteAddr string) error {
	// Parse the CIDR block
	_, ipnet, err := net.ParseCIDR(vpcCIDR)
	if err != nil {
		return fmt.Errorf("invalid VPC CIDR format '%s': %w", vpcCIDR, err)
	}

	// Extract IP address from RemoteAddr (format is "IP:port")
	if remoteAddr == "" {
		return fmt.Errorf("remote address is empty")
	}

	// Split off the port
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return fmt.Errorf("invalid remote address format '%s': %w", remoteAddr, err)
	}

	// Parse the IP address
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address '%s'", host)
	}

	// Check if the IP is within the CIDR block
	if !ipnet.Contains(ip) {
		return fmt.Errorf("IP address %s is not within VPC CIDR block %s", ip, vpcCIDR)
	}

	return nil
}
