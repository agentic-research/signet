package sigid

import (
	"fmt"

	"github.com/agentic-research/signet/pkg/policy"
	"github.com/agentic-research/signet/pkg/signet"
	"github.com/fxamacker/cbor/v2"
)

// CBOR field numbers for sigid extensions (reserved fields 20-23)
const (
	// FieldProvenance is the CBOR key for SignetAuthCell chains
	FieldProvenance = 20

	// FieldEnvironment is the CBOR key for environment attestations (future)
	FieldEnvironment = 21

	// FieldBoundary is the CBOR key for boundary constraints (future)
	FieldBoundary = 22

	// FieldAttestations is the CBOR key for signed attestations (future)
	FieldAttestations = 23
)

// TokenWithChain embeds a SignetAuthCell chain into a signet token's CBOR representation.
// This extends the token with sigid-specific field 20 (Provenance).
//
// The returned bytes are a valid CBOR-encoded token that can be unmarshaled back into
// a signet.Token, but also contains the chain data in field 20.
func TokenWithChain(token *signet.Token, chain []policy.SignetAuthCell) ([]byte, error) {
	if token == nil {
		return nil, fmt.Errorf("token is nil")
	}

	// Marshal the base token to CBOR
	tokenCBOR, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal token: %w", err)
	}

	// Unmarshal into a map so we can add field 20
	var tokenMap map[int]interface{}
	if err := cbor.Unmarshal(tokenCBOR, &tokenMap); err != nil {
		return nil, fmt.Errorf("unmarshal token to map: %w", err)
	}

	// Marshal the chain
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create CBOR encoder: %w", err)
	}
	chainCBOR, err := encMode.Marshal(chain)
	if err != nil {
		return nil, fmt.Errorf("marshal chain: %w", err)
	}

	// Add field 20 (chain) to the token map
	tokenMap[FieldProvenance] = chainCBOR

	// Marshal the extended map back to CBOR
	extendedCBOR, err := encMode.Marshal(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("marshal extended token: %w", err)
	}

	return extendedCBOR, nil
}

// ChainFromToken extracts a SignetAuthCell chain from a signet token's CBOR representation.
// This reads sigid-specific field 20 (Provenance).
//
// Returns an error if field 20 is not present or cannot be decoded.
func ChainFromToken(tokenCBOR []byte) ([]policy.SignetAuthCell, error) {
	if len(tokenCBOR) == 0 {
		return nil, fmt.Errorf("token CBOR is empty")
	}

	// Unmarshal into a map to access field 20
	var tokenMap map[int]interface{}
	if err := cbor.Unmarshal(tokenCBOR, &tokenMap); err != nil {
		return nil, fmt.Errorf("unmarshal token to map: %w", err)
	}

	// Extract field 20 (chain)
	chainField, ok := tokenMap[FieldProvenance]
	if !ok {
		return nil, fmt.Errorf("field %d (provenance chain) not present in token", FieldProvenance)
	}

	// Field 20 should contain CBOR-encoded chain
	chainCBOR, ok := chainField.([]byte)
	if !ok {
		return nil, fmt.Errorf("field %d is not a byte array", FieldProvenance)
	}

	// Unmarshal the chain
	var chain []policy.SignetAuthCell
	if err := cbor.Unmarshal(chainCBOR, &chain); err != nil {
		return nil, fmt.Errorf("unmarshal chain: %w", err)
	}

	return chain, nil
}

// TokenFromCBOR unmarshals a CBOR-encoded token (possibly with sigid extensions)
// back into a signet.Token. The sigid fields (20-23) are ignored.
func TokenFromCBOR(tokenCBOR []byte) (*signet.Token, error) {
	return signet.Unmarshal(tokenCBOR)
}
