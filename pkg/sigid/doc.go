// Package sigid is an Identity Context Provider that extracts provenance, environment,
// and boundary claims from signet authentication tokens.
//
// # Architecture Position
//
// sigid sits between authentication and authorization:
//
//	Authentication (signet) → Identity Context (sigid) → Authorization (capabilities)
//	"Do you have the key?" → "Who are you, how did you get here?" → "What can you do?"
//
// # Design Principles
//
// 1. Offline-first: No network calls during context extraction or validation
// 2. Privacy-preserving: Use pairwise pseudonymous identifiers (ppids), not cleartext identities
// 3. Backward compatible: sigid fields are optional; legacy signet tokens work
// 4. Extensible: Plugin architecture for attestation providers and boundary validators
//
// # Token Format
//
// sigid extends signet tokens with reserved CBOR fields:
//   - Field 20: Provenance (Actor/Delegator/Chain)
//   - Field 21: Environment (Cluster/Image/Attestations)
//   - Field 22: Boundary (VPC/Region/Domain)
//   - Field 23: Attestations (Signed claims)
//
// Fallback: If fields 20-23 are absent, derive from legacy Actor (field 14) and Delegator (field 15) claims.
//
// # Example Usage
//
//	// Extract context from a signet token
//	provider := basic.NewProvider()
//	ctx, err := provider.ExtractContext(signetToken)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Access identity information
//	fmt.Printf("Actor: %s\n", ctx.Provenance.ActorPPID)
//	fmt.Printf("Cluster: %s\n", ctx.Environment.ClusterID)
//
// # Security Model
//
// Trust assumptions:
//   - signet has already verified proof-of-possession correctly
//   - The token issuer is authoritative for identity claims
//   - Attestation providers are honest
//
// Not in scope:
//   - Authentication (signet's responsibility)
//   - Authorization decisions (capability protocol's responsibility)
//   - Policy management
package sigid
