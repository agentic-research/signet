# ADR-004: Bridge Certificates for Federated Identity

**Status:** Draft

**Date:** 2025-10-03

**Authors:** James Gardner

## Context

Signet provides privacy-preserving authentication through anonymous certificates signed by private roots. However, certain scenarios require proving properties about the user's identity (KYC compliance, organizational affiliation, reputation) without permanently linking their anonymous and public identities.

Current bearer token systems conflate access and identity. We need a mechanism that:
- Maintains cryptographic unlinkability between anonymous and public identities
- Allows optional, selective disclosure of verified properties
- Prevents correlation across sessions
- Works with existing PKI infrastructure (CT logs, Sigstore)


## Related Documents

- **[ADR-001: Signet Tokens](./ADR-001-signet-tokens.md)** - Core protocol and token design
- **[ADR-002: Protocol Specification](./ADR-002-protocol-spec.md)** - Wire format specification
- **[ADR-003: SDK Architecture](./ADR-003-sdk.md)** - Client implementation guide
- **[Feature Matrix](../FEATURE_MATRIX.md)** - Implementation status across all components

## Decision

Implement **bridge certificates** - ephemeral, single-use X.509 certificates that bind a public identity's verified properties to an anonymous session's ephemeral key, without revealing the private root.

### Core Mechanism

1. **Two Independent Roots**
   - Private root: Generated locally, signs anonymous certificates with ppids
   - Public root: Traditional identity (GitHub, Google, employer), published in CT logs

2. **Bridge Certificate Flow**
   ```
   User generates anonymous cert (private root) + ephemeral key
   ↓
   User requests bridge cert from public root
   Bridge cert: public root signs ephemeral key + capabilities
   ↓
   User presents both certs to relying party
   Anonymous cert proves capability
   Bridge cert proves verified properties
   ```

3. **Relying Party Validation**
   - Validates bridge cert via standard PKIX/CT/Sigstore
   - Extracts capability list from bridge cert extension
   - Validates anonymous cert signature with ephemeral key
   - Verifies Signet token capabilities ⊆ bridge cert capabilities
   - **Never sees or validates the private root**

### Wire Format

#### X.509 Extension (Critical)

```asn1
id-signet-capability-attestation OBJECT IDENTIFIER ::=
  { iso(1) identified-organization(3) dod(6) internet(1)
    private(4) enterprise(1) signet(TBD) 1 }

SignetCapabilityAttestation ::= SEQUENCE {
  version      INTEGER DEFAULT 1,
  capabilities SEQUENCE OF UTF8String,
  audience     SEQUENCE OF UTF8String,      -- Restrict to specific RPs
  notAfter     GeneralizedTime OPTIONAL,    -- Independent expiry
  constraints  SEQUENCE OF Constraint OPTIONAL
}

Constraint ::= SEQUENCE {
  type  OBJECT IDENTIFIER,
  value UTF8String
}
```

**Note:** OID arc reserves next node for v2 extensions without breaking compatibility.

#### Capability URI Grammar (ABNF)

```abnf
capability-uri = "urn:signet:cap:" action ":" resource *(":" constraint)
action         = 1*ALPHA *("-" / "_")
resource       = domain [ abs-path ]
constraint     = key "=" value
domain         = <RFC 3986 host>
abs-path       = <RFC 3986 path>
```

**Examples:**
- `urn:signet:cap:read:api.example.com/users`
- `urn:signet:cap:write:repo:github.com/acme/widget`
- `urn:signet:cap:payment:maxUSD=5000:bank.example.com`

### Delegated Bridge Signing

To avoid round-trips to the public root, users obtain a short-lived (hours) **delegate certificate**:

- Chains to public root
- `KeyUsage`: `digitalSignature` only
- `ExtendedKeyUsage`: `id-kp-signet-bridge-delegate` (new OID)
- Enables local bridge cert issuance without public root online

**Chain Depth Constraint:** Relying parties MUST accept exactly one intermediate certificate (the delegate) between the public root and the bridge certificate. This prevents downgrade attacks where an attacker attempts to insert additional delegation layers.

Relying parties validate the delegate cert chains to a trusted public root and carries the special EKU.

### Privacy Protection

#### CT Log Publication
Bridge certs are published to CT logs with privacy protection:
- Log entry format: `0x00 || SHA-256(ephemeralPublicKey) || capabilities || notAfter`
- Prefix byte (0x00) distinguishes privacy-protected entries from normal precerts
- Full cert presented to relying party enables verification
- Prevents ephemeral key from becoming correlation point

**Note:** The prefix byte is reserved for future extensibility to support additional entry types.

#### Timing Decorrelation
- Bridge cert published at random delay T + [0, 24h]
- Multiple dummy bridge certs published simultaneously
- Breaks timing correlation between cert issuance and anonymous session

### Capability Verification

Relying parties perform subset verification with normalization:

```
1. Parse capabilities from bridge cert extension
2. Parse capabilities from Signet token
3. Normalize both sets:
   - Drop constraints with unrecognized keys
   - Sort remaining tuples canonically
4. Verify: token_caps ⊆ bridge_caps
```

This prevents false rejects from ordering or unknown constraints.

### Revocation

Bridge certs are short-lived (minutes), making CRL/OCSP unnecessary. For early revocation:
- Publish SHA-256(ephemeralPublicKey) to revocation transparency log
- Relying parties poll log (entries older than cert's `notAfter` ignored)
- Simple one-bit check with minimal infrastructure

## Implementation Status

**Determined but may be refined during implementation:**
- Exact OID assignments (pending IANA/enterprise allocation)
- Delegate cert lifetime defaults (current: 24 hours)
- CT log delay distribution (current: uniform [0, 24h])
- Capability URI namespace governance
- Revocation transparency log format

**Ready for implementation:**
- X.509 extension structure
- Capability URI grammar
- Validation algorithm
- Delegated signing model

### Ecosystem Adoption Strategy

**Rejection Telemetry:** Non-supporting relying parties will reject the critical extension with a certificate validation error. Implementers SHOULD log the unknown extension OID once per RP (not per-request) to measure ecosystem readiness. This telemetry informs the decision to mark the extension as critical in production deployments.

**Gradual Rollout:** Initial deployments MAY mark the extension as non-critical to enable soft adoption, upgrading to critical once telemetry shows sufficient ecosystem support.

## Security Properties

| Property | Implementation |
|----------|---------------|
| Unlinkability | Private/public roots cryptographically independent |
| Selective Disclosure | Capabilities scoped per bridge cert |
| Replay Prevention | Single-use ephemeral keys |
| Timing Resistance | Delayed, noisy CT publication |
| Key Correlation Prevention | Hashed public keys in CT logs |
| Capability Enforcement | Cryptographic binding via signatures |

### Threat Model

**Colluding Relying Parties:** Even if multiple RPs share CT logs, they only observe hashed ephemeral keys. Without the full bridge certificate, sessions remain uncorrelatable across services.

**Compromised Delegate Key:** Maximum damage is bounded by the delegate certificate's short lifetime (hours) and the capabilities it was authorized to issue. The private root remains unaffected and can continue issuing anonymous certificates independently.

## Migration Path

1. **Phase 1:** Current Signet with private roots and ppids
2. **Phase 2:** Add X.509 extension support for capability attestation
3. **Phase 3:** Implement delegated bridge cert issuance
4. **Phase 4:** CT log integration with privacy protection
5. **Phase 5:** Public root integration (GitHub, employer OIDC, etc.)

## Consequences

### Positive
- Decouples access from identity at cryptographic level
- Maintains full anonymity for non-federated use cases
- Single-use bridge certs prevent persistent tracking
- Works with existing PKI infrastructure
- No allow-lists required at relying parties
- Instant revocation through short TTLs

### Negative
- Requires new X.509 extension (ecosystem adoption needed)
- CT log infrastructure must support privacy-preserving publication
- Delegated signing adds key management complexity
- Public roots must implement bridge cert issuance
- Capability URI namespace requires governance

### Open Questions
- Multi-signature bridge certs (M-of-N public roots)?
- Integration with hardware security modules?
- Capability delegation chains (bridge cert delegates to sub-capabilities)?
- Anonymous credential systems (BBS+ signatures) as future evolution?

## References

- **[ADR-001: Signet Tokens](./ADR-001-signet-tokens.md)** - Core protocol
- **[ADR-002: Protocol Specification](./ADR-002-protocol-spec.md)** - Wire format
- **[ADR-003: SDK Architecture](./ADR-003-sdk.md)** - Client implementation
- RFC 5280: X.509 Certificate and CRL Profile
- RFC 6962: Certificate Transparency
- Sigstore: Software supply chain security

## Acknowledgments

Bridge certificate mechanism design refined through collaboration with cryptographic protocol reviewers. Core insight: invert trust model so capabilities flow through public root attestation rather than private root disclosure.

---

*Enabling selective identity disclosure without sacrificing privacy*
