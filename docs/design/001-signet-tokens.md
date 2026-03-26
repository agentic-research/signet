# Signet v1 - Semantic PoP Tokens with CBOR+COSE


**Status:** Draft

**Date:** 2025-09-26

**Authors:** James Gardner / @jamestexas

Executive Summary
Signet v1 is a ground-up reimagining of authentication and authorization for modern cloud infrastructure. It replaces bearer tokens with proof-of-possession credentials, opaque permissions with semantic capabilities, and manual secret management with automated, ephemeral credentials.

Unlike traditional "zero trust" solutions that simply verify bearer tokens more frequently, Signet eliminates entire classes of vulnerabilities while actually improving developer experience.

Context
Current auth is fundamentally broken:

OAuth 2.0 + JWT has grown into a complex, network-dependent maze that's hostile to edge and offline cases
Developers manually manage secrets that are essentially permanent "God keys" waiting to be leaked
Debugging Cloud Run locally requires 15+ environment variables, each a potential security hole
"Zero Trust" solutions are just bearer tokens with more frequent checks
Permissions are opaque (arn:aws:iam::123456789012:role/MyRole) instead of semantic (["read", "env:prod"])
No real revocation - tokens float around until expiry regardless of compromise
No attribution - when something happens, we can't definitively say who did it and why
We want:

Simple auth with one mental model - no more choosing between OAuth flows
Offline verification on the fast path - sub-millisecond authorization
Real revocation semantics - instant in practice, not just theory
Proof-of-possession - stolen tokens are useless without the private key
Semantic capabilities - humans can understand permissions, machines can enforce them
Invisible complexity - developers just run signet login once, everything else is automatic
Rich audit context - every action carries its complete story, cryptographically signed
Decision
Adopt Signet v1: a complete authentication and authorization platform consisting of:

Core Protocol
Binary container: CBOR payload + COSE-Ed25519 signature, transmitted as SIG1.<b64url(cbor)>.<b64url(sig)>
Per-request PoP: Every API call carries a Signet-Proof header with ephemeral key ID (privacy-preserving)
Semantic capabilities: 128-bit capability hash with human-readable token list
Instant revocation: Via signed epoch feeds with grace period handling
Privacy-preserving: Per-token pairwise subject IDs, no fingerprinting
Identity-aware: Rich context including actor, delegator, and audit metadata
Developer Experience
Automated credentials: Smart CLI/SDKs that handle all cryptographic complexity
Just-in-time minting: Credentials created on-demand, expired after use
Context-aware: Different credentials for local dev vs production vs CI/CD
Zero configuration: No more 15 environment variables for local debugging
Progressive disclosure: Verbose modes show capabilities without exposing secrets
Operational Excellence
Impersonation support: SREs can debug as users with full audit trail
Delegation model: Services act on behalf of humans with clear attribution
Break-glass access: Emergency privileges with multi-party approval
Token lineage: Resources tagged with identity context at creation
Policy as code: Security policies in version-controlled YAML
Token Format (Normative)
Wire Format
SIG1.<b64url(CBOR payload)>.<b64url(COSE_Sign1 Ed25519 signature)>
CBOR Payload Structure
Key	Name	Type	Description
1	iss_id	tstr	Issuer identifier
2	aud_id	tstr	Audience identifier (optional)
3	sub_ppid	bstr(32B)	Per-token pairwise pseudonymous identifier
4	exp	uint	Expiration (epoch seconds)
5	nbf	uint	Not before
6	iat	uint	Issued at
7	cap_id	bstr(16B)	128-bit capability set hash
8	cap_ver	uint	Capability version/epoch (major.minor encoded, optional)
9	cnf	bstr(32B)	Confirmation ID — SHA-256 of bound master public key
10	kid	bstr	Key ID (optional)
11	cap_tokens	[* uint]	Semantic capability tokens (optional)
12	cap_custom	map	Custom constraints and metadata (optional)
13	jti	bstr(16B)	Token ID
14	act	map	Actor (for impersonation, optional)
15	del	map	Delegator (for delegation, optional)
16	aud_str	tstr	Audience string (for debugging, optional)
17	nonce	bstr(16B)	Nonce (optional)
18	eph_kid	bstr(32B)	Ephemeral key ID (optional)
19	epoch	uint	Revocation epoch (optional)
Capability Computation (Updated for 128-bit)
python
def compute_cap_id(cap_tokens):
    # Convert to canonical form
    token_ids = []
    for token in cap_tokens:
        if isinstance(token, int):
            token_ids.append(token)
        else:  # Custom string token - must be pre-registered
            token_id = issuer_lookup_registered_token(token)
            if not token_id:
                raise UnregisteredTokenError(token)
            token_ids.append(token_id)

    # Sort, deduplicate, hash to 128 bits
    canonical = sorted(set(token_ids))
    return trunc128(sha256(cbor_encode(canonical)))
Pairwise Identifier (Per-Token)
python
def generate_ppid(global_user_id, audience, jti, issuer_secret):
    """Generate unlinkable per-token identifier"""
    return HMAC_SHA256(
        key=issuer_secret,
        msg=global_user_id || audience || jti
    )
Per-Request Proof-of-Possession (Revised)
Signet-Proof Header Format (Ephemeral Key ID Based)
Signet-Proof: v=1; ts=1700000000; nonce=<b64url(16B)>;
             kid=<ephemeral_key_id>;
             proof=<b64url(signature)>
Proof Generation
python
def generate_pop_proof(request, private_key):
    # Generate ephemeral key ID (cached for session)
    kid = generate_ephemeral_kid()

    # Canonical string for signature
    canon = f"{method}\n{path}\n{host}\n{ts}\n{nonce}\n{jti}"
    if method in ["POST", "PUT"]:
        canon += f"\n{sha256_hex(body)}"

    # Sign with private key (ephemeral proof)
    proof = ed25519_sign(private_key, canon)

    # Cache kid → cnf_key_hash mapping at verifier
    return kid, proof
Verification Rules
kid maps to cached cnf_key_hash (never see public key twice)
ts within ±60s of server time (with monotonic clock handling)
nonce not seen before for this jti
Proof validates against cached key hash
Revocation System (Enhanced)
Snapshot Format with Grace Period
json
{
  "iss_id": 12,
  "major_epoch": 5421,  // Revocations
  "minor_epoch": 8732,  // Capability additions
  "issued_at": 1700000456,
  "not_after": 1700000516,
  "grace_period": 300,  // 5 minutes
  "caps": [
    {"cap_id": "...", "state": "active|revoked", "ver": 17}
  ],
  "keys": [
    {"kid": 7, "pk": "...", "revoked_at": null}
  ],
  "rotation_keys": [  // For GDPR compliance
    {"epoch": 5420, "key": "..."}
  ]
}
Freshness Requirements (With Grace Period)
Verifiers accept tokens when:

Snapshot major_epoch ≥ token's cap_ver.major, OR
Within grace period AND token TTL ≤ 5 minutes AND jti not seen
This prevents CDN outages from causing global brownouts.

Semantic Capability System
Registry Ranges
0x0001-0x00FF: Actions (read, write, delete, admin)
0x0100-0x01FF: Resource families (team:*, env:*, scope:*)
0x0200-0x02FF: Constraints (limit:*, until:*, if:*)
0x0300-0x03FF: Special operations (impersonate:*, delegate:*)
Custom Token Registration
All custom tokens MUST be pre-registered with issuer to prevent collision attacks:

python
# Registration required before use
issuer.register_custom_token(
    name="acme:team:platform",
    id=compute_deterministic_id("acme:team:platform")
)
Client Implementation: Automated Just-in-Time Credentials
Developer Workflow
bash
# One-time setup (refresh token → OS keychain)
$ signet login
Opening browser for authentication...
✓ Authenticated as james@acme.com

# Everything else is automatic
$ signet api get /users
✓ Fetched ephemeral credential (expires in 5min)
✓ Retrieved user list

# Local development with zero configuration
$ signet local-dev start
✓ Detected local environment
✓ Fetched development credential
✓ Configured emulators
✓ Ready on http://localhost:8080
Supply Chain Security
Reproducible builds with signed binaries (sigstore)
Key pinning for update channel
Paranoid mode option where OS keychain holds private key
Advanced Operational Scenarios
1. Impersonation (SRE Debugging)
python
# Token structure when SRE impersonates user
{
    3: generate_ppid("jane", audience, jti, secret),  # Unique per token
    11: jane_capabilities,     # User's permissions
    14: {  # Actor claim
        "sub_ppid": generate_ppid("james-sre", audience, jti, secret),
        "iss_id": 1
    },
    12: {  # Audit context
        "jira_ticket": "SRE-4512",
        "reason": "Debugging settings bug",
        "mfa_verified": True
    }
}
2. Key Rotation Handling
When issuer key rotates:

python
# Old tokens remain valid until expiry
snapshot.keys.append({
    "kid": old_kid,
    "pk": old_public_key,
    "revoked_at": now() + max_token_ttl
})
Migration Strategy
Phase 1: Wrapper Mode (Months 1-3)
Accept existing OAuth/JWT tokens
Mint Signet tokens internally
Map scopes to semantic capabilities
No client changes required
Phase 2: Hybrid Mode (Months 4-6)
Roll out smart CLI/SDKs
Enable PoP on sensitive endpoints
Maintain backward compatibility
Collect metrics on adoption
Phase 3: Native Mode (Months 7-12)
Enforce Signet everywhere
Disable legacy JWT support
Maintain exceptions list for partners
Complete migration tools
Security Properties
Property	Implementation
Theft Resistance	Ephemeral key PoP with per-request proofs
Replay Prevention	Timestamp + nonce + cache window
Instant Revocation	Major/minor epochs + grace periods
Confused Deputy	Mandatory iss/aud/sub validation
Privacy	Per-token ppids, no correlation
Collision Resistance	128-bit cap_id + registered customs
Attribution	Actor/delegator claims + lineage
Future-Proof	COSE algorithm agility for PQC
Performance Characteristics
Token size: <250 bytes typical, 300 bytes max
Verification time: <1ms offline, <10ms with cache
Credential fetch: P50: 50ms, P99: 200ms
Snapshot distribution: CDN-cached, grace period handling
Memory overhead: ~1KB per cached credential
Data Retention & GDPR
Cryptographic shredding: Rotation keys enable ppid unlinking
Log retention: Tokens auto-expire after 5 minutes
Right to be forgotten: Delete HMAC key → ppids become unlinkable
Rollout Checklist
Core Infrastructure
 Issuer service with HA deployment
 Snapshot distribution via CDN with signed objects
 Major/minor epoch management
 Key rotation automation with grace periods
Client Tooling
 Smart CLI for Mac/Linux/Windows with signed binaries
 Go SDK with comprehensive packages
 HTTP middleware for standard net/http
 gRPC interceptors for service integration
Integration Components
 OAuth/OIDC wrapper service
 Envoy/nginx auth modules
 Kubernetes admission webhook
 Terraform provider
Operational Readiness
 Runbooks for CDN outages
 Dashboard for auth metrics
 Audit log aggregation
 Compliance reports
Success Metrics
Security: 100% of tokens with PoP, zero long-lived credentials
Performance: P99 verification <10ms, P99 fetch <200ms
Adoption: 80% of services migrated within 6 months
Developer Experience: Setup time <1 minute, zero manual secrets
Operational: MTTR for revocation <60s, full audit trail coverage
Consequences
Positive
Eliminates bearer token theft - PoP makes stolen tokens useless
Real revocation - Grace periods prevent brownouts
Developer productivity - No more secret management
Semantic clarity - Humans understand permissions
Complete attribution - Every action fully auditable
Offline-first - Sub-millisecond local verification
Negative
Toolchain dependency - Standard tools need wrappers
Migration complexity - Requires phased rollout
Operational overhead - Issuer becomes critical path
Snapshot distribution - New infrastructure component
Acknowledgments
This design incorporates critical security feedback from initial review, particularly:

128-bit capability IDs to prevent collision attacks
Ephemeral key IDs for PoP to prevent key correlation
Grace periods for snapshot freshness
Per-token ppids for unlinkability
Supply chain security for SDK distribution

## Implementation Maturity

Current state of implementation vs specification:

### Protocol Features
| Feature | Specification | Implementation | Status |
|---------|--------------|----------------|--------|
| CBOR Token Structure | ✅ Complete | ✅ Complete | Production |
| Ed25519 Signatures | ✅ Complete | ✅ Complete | Production |
| Ephemeral Key IDs | ✅ Complete | ✅ Complete | Production |
| Capability Hashing | ✅ Complete | 🚧 In Progress | Beta |
| Revocation Epochs | ✅ Complete | ⏳ Planned | Design |
| Pairwise Identifiers | ✅ Complete | ⏳ Planned | Design |

### Ecosystem Support
| Component | Status | Notes |
|-----------|--------|-------|
| Go Library (libsignet) | ✅ Production | Reference implementation |
| Go SDK | ✅ Production | Full feature parity |
| pkg/crypto/epr | ✅ Production | Ephemeral proof library |
| [go-cms](https://github.com/agentic-research/go-cms) (external) | ✅ Production | Ed25519 CMS/PKCS#7 — external dependency |
| signet-git | ✅ Production | Git signing application |
| HTTP Middleware | 🚧 Development | In progress |

Implementation status is tracked in the project's bead system.

## Related Documents

- **[002: Protocol Specification](./002-protocol-spec.md)** - Wire format and protocol details
- **[003: SDK Architecture](./003-sdk.md)** - Client library implementation guide
- **[Architecture Overview](../../ARCHITECTURE.md)** - System design and principles

References
CBOR: RFC 8949
COSE: RFC 8152
Ed25519: RFC 8032
Capability-Based Security: Miller, 2006
BeyondCorp: Google, 2014 (what not to do)
"The best auth system is the one developers don't have to think about."
