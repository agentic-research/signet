package cell

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/policy"
	"github.com/agentic-research/signet/pkg/sigid"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/fxamacker/cbor/v2"
)

// testKey represents a test Ed25519 keypair
type testKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// generateTestKey creates a new test Ed25519 keypair
func generateTestKey(t *testing.T) *testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &testKey{Public: pub, Private: priv}
}

// signCell creates a signature over the cell data
// The signature is computed over the canonical CBOR encoding of the cell
// (with Signature field set to empty bytes)
func signCell(t *testing.T, cell *policy.SignetAuthCell, key *testKey) []byte {
	t.Helper()

	// Clone the cell and zero out the signature field for signing
	cellForSigning := *cell
	cellForSigning.Signature = []byte{}

	// Marshal to canonical CBOR
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}
	data, err := encMode.Marshal(&cellForSigning)
	if err != nil {
		t.Fatalf("failed to marshal cell for signing: %v", err)
	}

	// Sign with domain separation prefix (must match verifyCell)
	prefixed := append([]byte(cellDomainPrefix), data...)
	signature := ed25519.Sign(key.Private, prefixed)
	return signature
}

// createTestCell creates a test SignetAuthCell signed by the given key
func createTestCell(t *testing.T, resource string, owner []byte, key *testKey) *policy.SignetAuthCell {
	t.Helper()

	cell := &policy.SignetAuthCell{
		Resource: resource,
		Owner:    owner,
		Group:    nil, // No group for simple test
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"*"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{
			Allow: []string{},
			Deny:  []string{},
		},
		OtherPermissions: policy.PolicyStatement{
			Allow: []string{},
			Deny:  []string{},
		},
		Signature: nil, // Will be set below
	}

	// Sign the cell
	cell.Signature = signCell(t, cell, key)

	return cell
}

// createMockToken creates a bare signet.Token with random fields for testing.
// The caller is responsible for embedding chain data (via token.Actor or CBOR field 20).
func createMockToken(t *testing.T) *signet.Token {
	t.Helper()

	// Create basic token fields
	confirmationID := make([]byte, 32)
	ephemeralKeyID := make([]byte, 32)
	nonce := make([]byte, 16)
	jti := make([]byte, 16)

	_, _ = rand.Read(confirmationID)
	_, _ = rand.Read(ephemeralKeyID)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(jti)

	now := time.Now().Unix()

	// Create token with basic fields
	token := &signet.Token{
		IssuerID:       "test-issuer",
		SubjectPPID:    ephemeralKeyID,
		ExpiresAt:      now + 3600,
		NotBefore:      now,
		IssuedAt:       now,
		ConfirmationID: confirmationID,
		EphemeralKeyID: ephemeralKeyID,
		CapabilityID:   ephemeralKeyID[:16],
		JTI:            jti,
		Nonce:          nonce,
	}

	return token
}

// TestExtractContext_ValidChain tests extracting context from a valid SignetAuthCell chain
func TestExtractContext_ValidChain(t *testing.T) {
	// Create a two-link chain:
	// Root cell (self-signed by rootKey)
	// -> Child cell (signed by rootKey, owned by childKey)

	rootKey := generateTestKey(t)
	childKey := generateTestKey(t)

	// Root cell: resource="root", owner=rootKey, signed by rootKey
	rootCell := createTestCell(t, "root", rootKey.Public, rootKey)

	// Child cell: resource="root:child", owner=childKey, signed by rootKey
	// (rootKey is authorizing childKey to own the sub-resource)
	childCell := &policy.SignetAuthCell{
		Resource: "root:child",
		Owner:    childKey.Public,
		Group:    nil,
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"read", "write"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{
			Allow: []string{},
			Deny:  []string{},
		},
		OtherPermissions: policy.PolicyStatement{
			Allow: []string{},
			Deny:  []string{},
		},
		Signature: nil,
	}
	// Sign childCell with rootKey (parent delegates authority)
	childCell.Signature = signCell(t, childCell, rootKey)

	// Create chain
	chain := []policy.SignetAuthCell{*rootCell, *childCell}

	// Create mock token with the chain
	token := createMockToken(t)

	// For now, we'll temporarily store the chain in the token's Actor field
	// (This is a test hack - in reality it would be in field 20)
	// Marshal the chain to CBOR
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}
	chainCBOR, err := encMode.Marshal(chain)
	if err != nil {
		t.Fatalf("failed to marshal chain: %v", err)
	}

	// Store chain in Actor field for testing
	token.Actor = map[string]interface{}{
		"chain": chainCBOR,
	}

	// Create provider and extract context (nil secret for backward compat)
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)
	// Assertions
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}

	if ctx.Provenance == nil {
		t.Fatal("expected non-nil provenance")
	}

	// The actor should be derived from the final cell's owner (childKey)
	// For now, we'll check that the PPID is derived from childKey.Public
	expectedPPID := sha256.Sum256(childKey.Public)
	if ctx.Provenance.ActorPPID == "" {
		t.Error("expected non-empty ActorPPID")
	}

	t.Logf("ActorPPID: %s", ctx.Provenance.ActorPPID)
	t.Logf("Expected PPID prefix: %x", expectedPPID[:8])
}

// TestExtractContext_InvalidSignature tests that a chain with an invalid signature is rejected
func TestExtractContext_InvalidSignature(t *testing.T) {
	rootKey := generateTestKey(t)

	// Create a cell with a valid structure but corrupt the signature
	cell := createTestCell(t, "root", rootKey.Public, rootKey)

	// Corrupt the signature by flipping some bits
	cell.Signature[0] ^= 0xFF
	cell.Signature[1] ^= 0xFF

	chain := []policy.SignetAuthCell{*cell}
	token := createMockToken(t)

	// Marshal and store chain
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}
	chainCBOR, err := encMode.Marshal(chain)
	if err != nil {
		t.Fatalf("failed to marshal chain: %v", err)
	}
	token.Actor = map[string]interface{}{
		"chain": chainCBOR,
	}

	// Try to extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)

	// Should fail with signature verification error
	if err == nil {
		t.Error("expected error for invalid signature, got nil")
	}
	if ctx != nil {
		t.Error("expected nil context on error")
	}

	t.Logf("Got expected error: %v", err)
}

// TestExtractContext_WrongSigner tests that a child cell signed by the wrong key is rejected
func TestExtractContext_WrongSigner(t *testing.T) {
	rootKey := generateTestKey(t)
	childKey := generateTestKey(t)
	wrongKey := generateTestKey(t) // A third key that shouldn't be signing anything

	// Root cell (self-signed)
	rootCell := createTestCell(t, "root", rootKey.Public, rootKey)

	// Child cell owned by childKey, but signed by wrongKey (not rootKey!)
	childCell := &policy.SignetAuthCell{
		Resource: "root:child",
		Owner:    childKey.Public,
		Group:    nil,
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"read"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{},
		OtherPermissions: policy.PolicyStatement{},
		Signature:        nil,
	}
	// Sign with wrongKey instead of rootKey (this is the error)
	childCell.Signature = signCell(t, childCell, wrongKey)

	chain := []policy.SignetAuthCell{*rootCell, *childCell}
	token := createMockToken(t)

	// Marshal and store chain
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}
	chainCBOR, err := encMode.Marshal(chain)
	if err != nil {
		t.Fatalf("failed to marshal chain: %v", err)
	}
	token.Actor = map[string]interface{}{
		"chain": chainCBOR,
	}

	// Try to extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)

	// Should fail with verification error
	if err == nil {
		t.Error("expected error for wrong signer, got nil")
	}
	if ctx != nil {
		t.Error("expected nil context on error")
	}

	t.Logf("Got expected error: %v", err)
}

// TestExtractContext_MalformedCBOR tests that malformed CBOR in the token is handled gracefully
func TestExtractContext_MalformedCBOR(t *testing.T) {
	token := createMockToken(t)

	// Put invalid CBOR data in the chain field
	token.Actor = map[string]interface{}{
		"chain": []byte{0xFF, 0xFF, 0xFF, 0xFF}, // Invalid CBOR
	}

	// Try to extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)

	// Should fail with CBOR unmarshal error
	if err == nil {
		t.Error("expected error for malformed CBOR, got nil")
	}
	if ctx != nil {
		t.Error("expected nil context on error")
	}

	t.Logf("Got expected error: %v", err)
}

// TestExtractContext_EmptyChain tests that an empty chain is rejected
func TestExtractContext_EmptyChain(t *testing.T) {
	token := createMockToken(t)

	// Marshal empty chain
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}
	chainCBOR, err := encMode.Marshal([]policy.SignetAuthCell{})
	if err != nil {
		t.Fatalf("failed to marshal chain: %v", err)
	}
	token.Actor = map[string]interface{}{
		"chain": chainCBOR,
	}

	// Try to extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)

	// Should fail with empty chain error
	if err == nil {
		t.Error("expected error for empty chain, got nil")
	}
	if ctx != nil {
		t.Error("expected nil context on error")
	}

	t.Logf("Got expected error: %v", err)
}

// TestExtractContext_NoActorField tests that missing Actor field is handled
func TestExtractContext_NoActorField(t *testing.T) {
	token := createMockToken(t)
	token.Actor = nil // No actor field

	// Try to extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContext(token)

	// Should fail with missing actor error
	if err == nil {
		t.Error("expected error for missing actor field, got nil")
	}
	if ctx != nil {
		t.Error("expected nil context on error")
	}

	t.Logf("Got expected error: %v", err)
}

// TestExtractContextFromCBOR_ValidChain tests the production path using CBOR field 20
func TestExtractContextFromCBOR_ValidChain(t *testing.T) {
	// Create a two-link chain with proper signatures
	rootKey := generateTestKey(t)
	childKey := generateTestKey(t)

	rootCell := createTestCell(t, "root", rootKey.Public, rootKey)

	childCell := &policy.SignetAuthCell{
		Resource: "root:child",
		Owner:    childKey.Public,
		Group:    nil,
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"read", "write"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{},
		OtherPermissions: policy.PolicyStatement{},
		Signature:        nil,
	}
	childCell.Signature = signCell(t, childCell, rootKey)

	chain := []policy.SignetAuthCell{*rootCell, *childCell}

	// Create a basic token
	token := createMockToken(t)

	// Embed the chain in field 20 using TokenWithChain
	tokenCBOR, err := sigid.TokenWithChain(token, chain)
	if err != nil {
		t.Fatalf("failed to create token with chain: %v", err)
	}

	// Extract context using the production method
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContextFromCBOR(tokenCBOR)
	// Assertions
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}

	if ctx.Provenance == nil {
		t.Fatal("expected non-nil provenance")
	}

	if ctx.Provenance.ActorPPID == "" {
		t.Error("expected non-empty ActorPPID")
	}

	// Verify the chain has 2 links
	if len(ctx.Provenance.Chain) != 2 {
		t.Errorf("expected chain length 2, got %d", len(ctx.Provenance.Chain))
	}

	t.Logf("Successfully extracted context from CBOR field 20")
	t.Logf("ActorPPID: %s", ctx.Provenance.ActorPPID)
	t.Logf("Chain length: %d", len(ctx.Provenance.Chain))
}

// TestTokenWithChain_RoundTrip tests that we can embed and extract a chain
func TestTokenWithChain_RoundTrip(t *testing.T) {
	rootKey := generateTestKey(t)
	rootCell := createTestCell(t, "test-resource", rootKey.Public, rootKey)
	chain := []policy.SignetAuthCell{*rootCell}

	// Create a token
	token := createMockToken(t)

	// Embed the chain in field 20
	tokenCBOR, err := sigid.TokenWithChain(token, chain)
	if err != nil {
		t.Fatalf("failed to embed chain: %v", err)
	}

	// Extract the chain back
	extractedChain, err := sigid.ChainFromToken(tokenCBOR)
	if err != nil {
		t.Fatalf("failed to extract chain: %v", err)
	}

	// Verify the chain matches
	if len(extractedChain) != len(chain) {
		t.Errorf("chain length mismatch: expected %d, got %d", len(chain), len(extractedChain))
	}

	if extractedChain[0].Resource != chain[0].Resource {
		t.Errorf("resource mismatch: expected %s, got %s", chain[0].Resource, extractedChain[0].Resource)
	}

	// Verify the token can still be unmarshaled as a signet.Token
	reconstructedToken, err := sigid.TokenFromCBOR(tokenCBOR)
	if err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if reconstructedToken.IssuerID != token.IssuerID {
		t.Errorf("issuer mismatch after round-trip")
	}

	t.Log("Round-trip successful: chain embedded and extracted correctly")
}

// TestPPID_Deterministic tests that PPID derivation is deterministic
func TestPPID_Deterministic(t *testing.T) {
	issuerSecret := []byte("test-issuer-secret-12345")
	userKey := generateTestKey(t)

	// Create two cells with the same owner
	cell1 := createTestCell(t, "resource1", userKey.Public, userKey)
	cell2 := createTestCell(t, "resource2", userKey.Public, userKey)

	// Create two chains with the same cells
	chain1 := []policy.SignetAuthCell{*cell1}
	chain2 := []policy.SignetAuthCell{*cell2}

	// Extract context twice with the same issuer secret
	provider := NewProvider(issuerSecret)
	prov1 := provider.extractProvenance(chain1)
	prov2 := provider.extractProvenance(chain2)

	// PPIDs should be identical (deterministic)
	if prov1.ActorPPID != prov2.ActorPPID {
		t.Errorf("PPIDs should be deterministic: got %s and %s", prov1.ActorPPID, prov2.ActorPPID)
	}

	t.Logf("Deterministic PPID: %s", prov1.ActorPPID)
}

// TestPPID_Unlinkable tests that PPIDs are unlinkable across different issuers
func TestPPID_Unlinkable(t *testing.T) {
	// Same user, different issuer secrets
	issuerSecret1 := []byte("issuer-1-secret")
	issuerSecret2 := []byte("issuer-2-secret")
	userKey := generateTestKey(t)

	// Create cells with the same owner
	cell := createTestCell(t, "resource", userKey.Public, userKey)
	chain := []policy.SignetAuthCell{*cell}

	// Extract context with different issuer secrets
	provider1 := NewProvider(issuerSecret1)
	provider2 := NewProvider(issuerSecret2)

	prov1 := provider1.extractProvenance(chain)
	prov2 := provider2.extractProvenance(chain)

	// PPIDs should be different (unlinkable)
	if prov1.ActorPPID == prov2.ActorPPID {
		t.Error("PPIDs should be unlinkable across different issuers")
	}

	t.Logf("Issuer 1 PPID: %s", prov1.ActorPPID)
	t.Logf("Issuer 2 PPID: %s", prov2.ActorPPID)
}

// TestPPID_HMACvsSHA256 tests that HMAC produces different results than plain SHA256
func TestPPID_HMACvsSHA256(t *testing.T) {
	issuerSecret := []byte("issuer-secret")
	userKey := generateTestKey(t)

	cell := createTestCell(t, "resource", userKey.Public, userKey)
	chain := []policy.SignetAuthCell{*cell}

	// With HMAC (issuer secret)
	providerWithHMAC := NewProvider(issuerSecret)
	provWithHMAC := providerWithHMAC.extractProvenance(chain)

	// Without HMAC (no issuer secret)
	providerWithoutHMAC := NewProvider(nil)
	provWithoutHMAC := providerWithoutHMAC.extractProvenance(chain)

	// PPIDs should be different
	if provWithHMAC.ActorPPID == provWithoutHMAC.ActorPPID {
		t.Error("HMAC-based PPID should differ from SHA256-based PPID")
	}

	t.Logf("HMAC PPID: %s", provWithHMAC.ActorPPID)
	t.Logf("SHA256 PPID: %s", provWithoutHMAC.ActorPPID)
}

// TestPPID_DelegatorTracking tests that delegator PPIDs are correctly tracked
func TestPPID_DelegatorTracking(t *testing.T) {
	issuerSecret := []byte("issuer-secret")
	rootKey := generateTestKey(t)
	childKey := generateTestKey(t)

	// Two-link chain: root -> child
	rootCell := createTestCell(t, "root", rootKey.Public, rootKey)
	childCell := &policy.SignetAuthCell{
		Resource: "root:child",
		Owner:    childKey.Public,
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"*"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{},
		OtherPermissions: policy.PolicyStatement{},
	}
	childCell.Signature = signCell(t, childCell, rootKey)

	chain := []policy.SignetAuthCell{*rootCell, *childCell}

	// Extract provenance
	provider := NewProvider(issuerSecret)
	prov := provider.extractProvenance(chain)

	// ActorPPID should be from childKey
	childPPID := provider.derivePPID(childKey.Public)
	if prov.ActorPPID != childPPID {
		t.Errorf("ActorPPID mismatch: expected %s, got %s", childPPID, prov.ActorPPID)
	}

	// DelegatorPPID should be from rootKey
	rootPPID := provider.derivePPID(rootKey.Public)
	if prov.DelegatorPPID != rootPPID {
		t.Errorf("DelegatorPPID mismatch: expected %s, got %s", rootPPID, prov.DelegatorPPID)
	}

	// Chain should have both PPIDs
	if len(prov.Chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(prov.Chain))
	}
	if prov.Chain[0] != rootPPID {
		t.Errorf("Chain[0] should be root PPID")
	}
	if prov.Chain[1] != childPPID {
		t.Errorf("Chain[1] should be child PPID")
	}

	t.Logf("ActorPPID: %s", prov.ActorPPID)
	t.Logf("DelegatorPPID: %s", prov.DelegatorPPID)
	t.Logf("Chain: %v", prov.Chain)
}

// TestValidateContext_Fresh tests that a freshly extracted context validates successfully
func TestValidateContext_Fresh(t *testing.T) {
	provider := NewProvider(nil)

	// Create a fresh context
	ctx := &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: "test-ppid",
		},
		Environment: &sigid.Environment{},
		Boundary:    &sigid.Boundary{},
		ExtractedAt: time.Now(),
	}

	// Validate with nil request (no boundary checks)
	err := provider.ValidateContext(ctx, nil)
	if err != nil {
		t.Errorf("expected no error for fresh context, got: %v", err)
	}

	t.Log("Fresh context validated successfully")
}

// TestValidateContext_Stale tests that a stale context is rejected
func TestValidateContext_Stale(t *testing.T) {
	provider := NewProvider(nil)

	// Create a stale context (extracted 10 minutes ago)
	ctx := &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: "test-ppid",
		},
		Environment: &sigid.Environment{},
		Boundary:    &sigid.Boundary{},
		ExtractedAt: time.Now().Add(-10 * time.Minute),
	}

	// Should fail validation
	err := provider.ValidateContext(ctx, nil)
	if err == nil {
		t.Error("expected error for stale context, got nil")
	}

	t.Logf("Stale context correctly rejected: %v", err)
}

// TestValidateContext_NilContext tests that nil context is rejected
func TestValidateContext_NilContext(t *testing.T) {
	provider := NewProvider(nil)

	err := provider.ValidateContext(nil, nil)
	if err == nil {
		t.Error("expected error for nil context, got nil")
	}

	t.Logf("Nil context correctly rejected: %v", err)
}

// TestValidateContext_BoundaryMatch tests successful domain boundary validation
func TestValidateContext_BoundaryMatch(t *testing.T) {
	provider := NewProvider(nil)

	ctx := &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: "test-ppid",
		},
		Environment: &sigid.Environment{},
		Boundary: &sigid.Boundary{
			Domain: "example.com",
		},
		ExtractedAt: time.Now(),
	}

	// Create a request with matching domain
	req := &http.Request{
		Host: "example.com",
	}

	err := provider.ValidateContext(ctx, req)
	if err != nil {
		t.Errorf("expected no error for matching domain, got: %v", err)
	}

	t.Log("Boundary validation passed for matching domain")
}

// TestValidateContext_BoundaryMismatch tests that domain mismatch is detected
func TestValidateContext_BoundaryMismatch(t *testing.T) {
	provider := NewProvider(nil)

	ctx := &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: "test-ppid",
		},
		Environment: &sigid.Environment{},
		Boundary: &sigid.Boundary{
			Domain: "example.com",
		},
		ExtractedAt: time.Now(),
	}

	// Create a request with different domain
	req := &http.Request{
		Host: "attacker.com",
	}

	err := provider.ValidateContext(ctx, req)
	if err == nil {
		t.Error("expected error for domain mismatch, got nil")
	}

	t.Logf("Domain mismatch correctly detected: %v", err)
}

// TestValidateContext_NoBoundary tests that nil boundary is accepted
func TestValidateContext_NoBoundary(t *testing.T) {
	provider := NewProvider(nil)

	ctx := &sigid.Context{
		Provenance: &sigid.Provenance{
			ActorPPID: "test-ppid",
		},
		Environment: &sigid.Environment{},
		Boundary:    nil, // No boundary specified
		ExtractedAt: time.Now(),
	}

	// Any request should be accepted
	req := &http.Request{
		Host: "any-domain.com",
	}

	err := provider.ValidateContext(ctx, req)
	if err != nil {
		t.Errorf("expected no error when no boundary specified, got: %v", err)
	}

	t.Log("Context with no boundary validated successfully")
}

// createTokenWithFullClaims creates a token with chain, environment, and boundary claims.
// This embeds data in CBOR fields 20 (chain), 21 (environment), and 22 (boundary).
func createTokenWithFullClaims(t *testing.T, chain []policy.SignetAuthCell, env *sigid.Environment, boundary *sigid.Boundary) []byte {
	t.Helper()

	// Create basic token
	token := createMockToken(t)

	// Marshal the base token to CBOR
	tokenCBOR, err := token.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	// Unmarshal into a map so we can add custom fields
	var tokenMap map[int]interface{}
	if err := cbor.Unmarshal(tokenCBOR, &tokenMap); err != nil {
		t.Fatalf("failed to unmarshal token to map: %v", err)
	}

	// Create canonical CBOR encoder
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create CBOR encoder: %v", err)
	}

	// Add field 20 (chain)
	chainCBOR, err := encMode.Marshal(chain)
	if err != nil {
		t.Fatalf("failed to marshal chain: %v", err)
	}
	tokenMap[sigid.FieldProvenance] = chainCBOR

	// Add field 21 (environment) if provided
	if env != nil {
		envCBOR, err := encMode.Marshal(env)
		if err != nil {
			t.Fatalf("failed to marshal environment: %v", err)
		}
		tokenMap[sigid.FieldEnvironment] = envCBOR
	}

	// Add field 22 (boundary) if provided
	if boundary != nil {
		boundaryCBOR, err := encMode.Marshal(boundary)
		if err != nil {
			t.Fatalf("failed to marshal boundary: %v", err)
		}
		tokenMap[sigid.FieldBoundary] = boundaryCBOR
	}

	// Marshal the extended map back to CBOR
	extendedCBOR, err := encMode.Marshal(tokenMap)
	if err != nil {
		t.Fatalf("failed to marshal extended token: %v", err)
	}

	return extendedCBOR
}

// TestExtractContext_FullClaims tests extracting context with Environment and Boundary claims
func TestExtractContext_FullClaims(t *testing.T) {
	// Create a valid chain
	rootKey := generateTestKey(t)
	childKey := generateTestKey(t)

	rootCell := createTestCell(t, "root", rootKey.Public, rootKey)
	childCell := &policy.SignetAuthCell{
		Resource: "root:child",
		Owner:    childKey.Public,
		Group:    nil,
		OwnerPermissions: policy.PolicyStatement{
			Allow: []string{"read", "write"},
			Deny:  []string{},
		},
		GroupPermissions: policy.PolicyStatement{},
		OtherPermissions: policy.PolicyStatement{},
		Signature:        nil,
	}
	childCell.Signature = signCell(t, childCell, rootKey)

	chain := []policy.SignetAuthCell{*rootCell, *childCell}

	// Create Environment and Boundary claims
	env := &sigid.Environment{
		ClusterID:   "prod-us-east-1",
		ImageDigest: "sha256:abcdef123456",
	}

	boundary := &sigid.Boundary{
		VPC:    "vpc-12345",
		Region: "us-east-1",
		Domain: "example.com",
	}

	// Create token with full claims
	tokenCBOR := createTokenWithFullClaims(t, chain, env, boundary)

	// Extract context
	provider := NewProvider(nil)
	ctx, err := provider.ExtractContextFromCBOR(tokenCBOR)
	// Assertions
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}

	// Check Provenance
	if ctx.Provenance == nil {
		t.Fatal("expected non-nil provenance")
	}
	if ctx.Provenance.ActorPPID == "" {
		t.Error("expected non-empty ActorPPID")
	}

	// Check Environment
	if ctx.Environment == nil {
		t.Fatal("expected non-nil environment")
	}
	if ctx.Environment.ClusterID != "prod-us-east-1" {
		t.Errorf("expected ClusterID 'prod-us-east-1', got '%s'", ctx.Environment.ClusterID)
	}
	if ctx.Environment.ImageDigest != "sha256:abcdef123456" {
		t.Errorf("expected ImageDigest 'sha256:abcdef123456', got '%s'", ctx.Environment.ImageDigest)
	}

	// Check Boundary
	if ctx.Boundary == nil {
		t.Fatal("expected non-nil boundary")
	}
	if ctx.Boundary.VPC != "vpc-12345" {
		t.Errorf("expected VPC 'vpc-12345', got '%s'", ctx.Boundary.VPC)
	}
	if ctx.Boundary.Region != "us-east-1" {
		t.Errorf("expected Region 'us-east-1', got '%s'", ctx.Boundary.Region)
	}
	if ctx.Boundary.Domain != "example.com" {
		t.Errorf("expected Domain 'example.com', got '%s'", ctx.Boundary.Domain)
	}

	t.Log("Successfully extracted full context with Environment and Boundary claims")
}

// TestValidateContext_VPCBoundary tests VPC CIDR boundary validation
func TestValidateContext_VPCBoundary(t *testing.T) {
	provider := NewProvider(nil)

	// Test case 1: IP within CIDR block should pass
	t.Run("IP within CIDR block", func(t *testing.T) {
		ctx := &sigid.Context{
			Provenance: &sigid.Provenance{
				ActorPPID: "test-ppid",
			},
			Environment: &sigid.Environment{},
			Boundary: &sigid.Boundary{
				VPC: "10.0.0.0/16", // CIDR block
			},
			ExtractedAt: time.Now(),
		}

		// Create request with IP inside the CIDR block
		req := &http.Request{
			RemoteAddr: "10.0.1.123:12345",
		}

		err := provider.ValidateContext(ctx, req)
		if err != nil {
			t.Errorf("expected no error for IP within CIDR block, got: %v", err)
		}

		t.Log("IP within CIDR block correctly validated")
	})

	// Test case 2: IP outside CIDR block should fail
	t.Run("IP outside CIDR block", func(t *testing.T) {
		ctx := &sigid.Context{
			Provenance: &sigid.Provenance{
				ActorPPID: "test-ppid",
			},
			Environment: &sigid.Environment{},
			Boundary: &sigid.Boundary{
				VPC: "10.0.0.0/16", // CIDR block
			},
			ExtractedAt: time.Now(),
		}

		// Create request with IP outside the CIDR block
		req := &http.Request{
			RemoteAddr: "192.168.1.10:54321",
		}

		err := provider.ValidateContext(ctx, req)
		if err == nil {
			t.Error("expected error for IP outside CIDR block, got nil")
		}

		t.Logf("IP outside CIDR block correctly rejected: %v", err)
	})

	// Test case 3: Multiple CIDR blocks - should validate against the first match
	t.Run("IP at edge of CIDR block", func(t *testing.T) {
		ctx := &sigid.Context{
			Provenance: &sigid.Provenance{
				ActorPPID: "test-ppid",
			},
			Environment: &sigid.Environment{},
			Boundary: &sigid.Boundary{
				VPC: "10.0.0.0/24", // Smaller CIDR block
			},
			ExtractedAt: time.Now(),
		}

		// Test edge case: first IP in range
		req1 := &http.Request{
			RemoteAddr: "10.0.0.1:12345",
		}

		err := provider.ValidateContext(ctx, req1)
		if err != nil {
			t.Errorf("expected no error for IP at start of CIDR block, got: %v", err)
		}

		// Test edge case: last IP in range (10.0.0.254 for /24)
		req2 := &http.Request{
			RemoteAddr: "10.0.0.254:12345",
		}

		err = provider.ValidateContext(ctx, req2)
		if err != nil {
			t.Errorf("expected no error for IP at end of CIDR block, got: %v", err)
		}

		// Test just outside the range
		req3 := &http.Request{
			RemoteAddr: "10.0.1.1:12345",
		}

		err = provider.ValidateContext(ctx, req3)
		if err == nil {
			t.Error("expected error for IP just outside CIDR block, got nil")
		}

		t.Log("CIDR edge cases validated correctly")
	})

	// Test case 4: Invalid VPC format should return error
	t.Run("Invalid VPC format", func(t *testing.T) {
		ctx := &sigid.Context{
			Provenance: &sigid.Provenance{
				ActorPPID: "test-ppid",
			},
			Environment: &sigid.Environment{},
			Boundary: &sigid.Boundary{
				VPC: "not-a-valid-cidr",
			},
			ExtractedAt: time.Now(),
		}

		req := &http.Request{
			RemoteAddr: "10.0.1.1:12345",
		}

		err := provider.ValidateContext(ctx, req)
		if err == nil {
			t.Error("expected error for invalid VPC CIDR format, got nil")
		}

		t.Logf("Invalid VPC format correctly rejected: %v", err)
	})

	// Test case 5: Missing RemoteAddr should be handled gracefully
	t.Run("Missing RemoteAddr", func(t *testing.T) {
		ctx := &sigid.Context{
			Provenance: &sigid.Provenance{
				ActorPPID: "test-ppid",
			},
			Environment: &sigid.Environment{},
			Boundary: &sigid.Boundary{
				VPC: "10.0.0.0/16",
			},
			ExtractedAt: time.Now(),
		}

		req := &http.Request{
			RemoteAddr: "", // Empty RemoteAddr
		}

		err := provider.ValidateContext(ctx, req)
		if err == nil {
			t.Error("expected error for missing RemoteAddr, got nil")
		}

		t.Logf("Missing RemoteAddr correctly handled: %v", err)
	})
}
