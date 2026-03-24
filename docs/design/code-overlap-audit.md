# Code Overlap Audit: signet / sigid / sigpol

**Date**: 2026-03-24
**Branch**: feat/sigid-sigpol-integration
**Reference**: ADR-011 section 6 (naming and package layout)

---

## Conceptual Boundaries

Per ADR-011:

| Component | Concern | Question It Answers |
|-----------|---------|---------------------|
| **signet** | Authorization / crypto | "Prove you hold this key" |
| **sigid** | Identity lifecycle | "Who are you?" |
| **sigpol** | Policy distribution | "What are you allowed to do? Are you still employed?" |

---

## Package Audit

### Legend

- **Owner**: `signet` = auth/crypto, `sigid` = identity, `sigpol` = policy, `shared` = foundational (stays in signet workspace root)
- **Action**: `stays` = no move needed, `move` = relocate, `split` = file contains mixed concerns

---

### pkg/crypto/ — SIGNET (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/crypto/algorithm/` | signet | stays | Core algorithm registry (Ed25519, ML-DSA-44). Pure crypto, no identity or policy. |
| `pkg/crypto/epr/` | signet | stays | Ephemeral Proof Routines — PoP verification. Core signet auth primitive. |
| `pkg/crypto/keys/` | signet | stays | Key management, signers, zeroization. Used by all three components but is fundamentally crypto infrastructure. |
| `pkg/crypto/cose/` | signet | stays | COSE Sign1 messages. Wire-format crypto, no identity semantics. |

**Imports**: `epr` depends on `algorithm`, `keys`. `cose` has no signet-internal deps.
**Imported by**: middleware, revocation, signet tokens, git, CLI.
**Risk**: None — clean foundational layer.

---

### pkg/signet/ — SIGNET (stays, but Token fields 14-15 overlap sigid)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/signet/token.go` | signet | stays | CBOR token structure. Defines fields 1-19. |
| `pkg/signet/sig1.go` | signet | stays | SIG1 wire format. Pure serialization. |
| `pkg/signet/capability.go` | **signet/sigpol boundary** | stays (signet owns the type; sigpol will *compute* capabilities) | `ComputeCapabilityID` and `ValidateCapabilityID` are crypto operations on capability tokens. The *values* in `CapTokens` are sigpol's domain, but the *hash computation* is signet's. |

**Overlap with sigid**: Token fields `Actor` (14) and `Delegator` (15) carry identity context. sigid already defines `FieldProvenance` (20) as the richer replacement. Fields 14-15 become legacy; sigid reads them as fallback (see `sigid/doc.go` lines 26-27).

**Overlap with sigpol**: Token fields `CapabilityID` (7), `CapTokens` (11), `CapCustom` (12) carry policy-computed values. sigpol will populate these; signet owns the wire format.

---

### pkg/oidc/ — SIGID (move)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/oidc/provider.go` | sigid | `sigid: pkg/oidc/` or `sigid/oidc/` | OIDC provider abstraction answers "who are you?" — identity verification, not auth proof. |
| `pkg/oidc/github.go` | sigid | moves with provider.go | GitHub Actions OIDC provider — identity binding for GHA. |
| `pkg/oidc/cloudflare.go` | sigid | moves with provider.go | Cloudflare Access provider — identity binding. |
| `pkg/oidc/config.go` | sigid | moves with provider.go | Provider config loading from YAML/env. |

**Why sigid**: The `Provider` interface answers "verify this OIDC token and tell me who the subject is" — this is identity extraction, not authorization. The `Claims` type (`Subject`, `Issuer`, `Extra`) is identity context.

**Note**: `MapCapabilities()` on the Provider interface straddles sigid/sigpol. It maps identity claims to capability URIs. This is the key integration seam — sigid extracts claims, sigpol resolves capabilities from those claims. Short-term, `MapCapabilities` stays on the provider; long-term, it moves to sigpol's policy evaluator.

**Dependencies**:
- Imports: `go-oidc/v3`, stdlib only. No signet-internal deps.
- Imported by: `cmd/signet/authority.go`, `cmd/signet/authority_oidc_test.go`.

---

### pkg/attest/x509/ — SIGID (move)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/attest/x509/localca.go` | sigid | `sigid: pkg/ca/` or `sigid/ca/` | LocalCA issues identity certificates — "who are you" bound to a key. |
| `pkg/attest/x509/bridge.go` | sigid | moves with localca.go | Bridge cert minting with capability extensions. Identity artifact. |
| `pkg/attest/x509/localca_signer_test.go` | sigid | moves with localca.go | Tests for identity cert issuance. |

**Why sigid**: The LocalCA's job is "mint an X.509 certificate that binds an identity to a key." This is identity issuance. The `OIDSubject` and `OIDIssuanceTime` OIDs are already duplicated in the sigid repo (`sigid/identity.go` lines 37-42 and `sigid/providers/cert/provider.go` lines 23-25).

**Bridge cert capability extensions** (`OIDSignetCapabilities` in bridge.go) straddle sigid/sigpol: the cert format is sigid's domain, but the capability values are sigpol's.

**Dependencies**:
- Imports: `pkg/crypto/keys` (signet)
- Imported by: `cmd/signet/authority.go`, `cmd/signet/sign.go`, `cmd/signet-git/bridge.go`, `pkg/git/sign.go`, `pkg/git/verify.go`

**Circular dep risk**: `attest/x509` depends on `crypto/keys` (signet). If moved to sigid module, sigid would need to import signet's `keys` package. This is fine in a Go workspace (sigid depends on signet, not vice versa).

---

### pkg/policy/ — SIGPOL (move)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/policy/evaluator.go` | sigpol | `sigpol: pkg/policy/` | Policy evaluation is the core sigpol concern. `PolicyEvaluator` interface and `StaticPolicyEvaluator` are the authorization decision point. |

**Why sigpol**: `evaluator.go` answers "is this subject allowed?" and "what capabilities do they get?" — pure policy.

**Dependencies**:
- Imports: stdlib only. No signet-internal deps.
- Imported by: `cmd/signet/authority.go`, `cmd/signet/authority_oidc_test.go`.

**ADR-011 expansion**: This package will grow to include `bundle.go`, `checker.go`, `cache.go`, `compiler.go` per ADR-011 section 6.

---

### pkg/http/middleware/ — SIGNET (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/http/middleware/*.go` | signet | stays | Request-level PoP verification. "Prove you hold the key for this request." Core signet auth. |

**Dependencies**:
- Imports: `algorithm`, `epr`, `header`, `revocation`, `signet` (all signet-internal)
- Imported by: `cmd/signet-proxy`, revocation tests

**No overlap**: Pure auth verification middleware.

---

### pkg/http/header/ — SIGNET (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/http/header/parser.go` | signet | stays | SIG1 header parsing. Wire format, no identity or policy. |

---

### pkg/revocation/ — SIGNET (stays, but pattern shared with sigpol)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/revocation/checker.go` | signet | stays | CA bundle revocation checking. Answers "has this key been revoked?" |
| `pkg/revocation/cabundle/` | signet | stays | Bundle fetching, caching, storage. |
| `pkg/revocation/types/` | signet | stays | `CABundle` type, `Fetcher`/`Storage` interfaces. |

**Overlap with sigpol**: ADR-011 proposes `PolicyChecker` (parallel to `CABundleChecker`) and `BundleCache` for policy bundles. The *pattern* is shared but the *types* are different. Consider extracting a shared `pkg/bundle/` infrastructure if the duplication becomes excessive.

**Dependencies**:
- Imports: `algorithm`, `keys`, `cabundle`, `types`, `signet`
- Imported by: middleware

---

### pkg/collections/ — SHARED (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/collections/*.go` | shared | stays | Generic concurrent data structures. Infrastructure used by authority (TokenCache). |

---

### pkg/errors/ — SHARED (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/errors/*.go` | shared | stays | `CodedError[T]` — foundational error handling. Used by EPR. |

---

### pkg/lifecycle/ — SHARED (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/lifecycle/*.go` | shared | stays | `SecureValue[T]` zeroization. Security infrastructure used by keys, git, CLI. |

---

### pkg/git/ — SIGNET (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/git/*.go` | signet | stays | Git commit signing/verification via CMS. Uses `attest/x509` for cert issuance and `crypto/keys` for signing. This is a signet *application* — signing artifacts. |

**Note**: `git/sign.go` depends on `attest/x509` (moving to sigid) and `crypto/keys` (stays in signet). After the move, `pkg/git` imports both signet and sigid — acceptable in a workspace.

---

### pkg/cli/ — SHARED (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/cli/config/` | shared | stays | Config loading (~/.signet). Shared across all commands. |
| `pkg/cli/keystore/` | shared | stays | Secure keystore. Used by sign, git, auth commands. |
| `pkg/cli/styles/` | shared | stays | Lipgloss styles. Cosmetic. |

---

### pkg/agent/ — SIGNET (stays)

| Path | Owner | Recommended Location | Reason |
|------|-------|---------------------|--------|
| `pkg/agent/*.go` | signet | stays | gRPC agent for key operations. Crypto/signing infrastructure. |

---

## Command Layer Audit

### cmd/signet/authority.go — SPLIT (sigid + sigpol + signet intertwined)

This is the most tangled file. 1780+ lines mixing three concerns:

| Lines (approx) | Concern | Owner | What It Does |
|----------------|---------|-------|-------------|
| 49-113 | CLI setup | shared | Cobra command definition, config loading |
| 114-313 | Server lifecycle | shared | HTTP server setup, graceful shutdown, rate limiting |
| 315-422 | Config types | **sigid** | `AuthorityConfig` (OIDC config, cert validity, session secret) |
| 424-479 | Authority struct | **sigid** | `Authority` — wraps LocalCA + OIDC registry |
| 481-562 | Cert minting | **sigid** | `mintClientCertificate` — identity issuance |
| 563-613 | Key parsing | signet | `parsePublicKeyBytes` — crypto utility |
| 615-663 | Token/session types | shared | `OIDCServer`, `TokenCache`, `SessionData` |
| 664-771 | OIDC server setup | **sigid** | `newOIDCServer` — OIDC provider config |
| 773-991 | Login/callback | **sigid** | `handleLogin`, `handleCallback` — OIDC auth flow |
| 993-1490 | Landing/helpers | shared | HTML landing page, rate limiter, logging middleware |
| 1492-1782 | Token exchange | **sigid+sigpol** | `handleExchangeToken` — OIDC verify (sigid) + policy evaluate (sigpol) + cert mint (sigid) |

**Recommendation**: This file should be decomposed into:
1. **sigid authority server** — OIDC verification, cert minting, session management
2. **sigpol policy hook** — `policyEvaluator.Evaluate()` call site (lines 1682-1708)
3. **signet crypto utilities** — `parsePublicKeyBytes` (could move to `pkg/crypto/keys`)

---

### cmd/signet/auth_login.go — SIGID (client-side identity flow)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/auth_login.go` | sigid | OAuth2+PKCE browser flow to obtain identity cert. Client-side identity provisioning. |

**Dependencies**: `pkg/crypto/keys` (signet), `pkg/cli/styles` (shared).

---

### cmd/signet/auth_register.go — SIGID (headless identity provisioning)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/auth_register.go` | sigid | GitHub token-based agent registration. Headless identity provisioning. |

---

### cmd/signet/auth_status.go — SIGID (identity cert status)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/auth_status.go` | sigid | Shows MCP cert expiry — identity lifecycle query. |

---

### cmd/signet/auth.go — SIGID (parent command)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/auth.go` | sigid | Parent `auth` subcommand group. |

---

### cmd/signet/authority_exchange.go — SIGID (client-side token exchange)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/authority_exchange.go` | sigid | Client-side GHA OIDC token exchange for bridge cert. |

---

### cmd/signet/authority_setup_resign.go — SIGID (CI/CD identity setup)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/authority_setup_resign.go` | sigid | Configures GHA secrets for post-merge re-signing. Identity infrastructure. |

---

### cmd/signet/sign.go — SIGNET (stays)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/sign.go` | signet | File signing with ephemeral certs. Core signing operation. |

---

### cmd/signet/ca_bundle_server.go — SIGNET (stays, pattern shared with sigpol)

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet/ca_bundle_server.go` | signet | CA bundle serving. sigpol will have a parallel policy bundle server. |

---

### Other binaries

| Path | Owner | Reason |
|------|-------|--------|
| `cmd/signet-git/` | signet | Git integration. Signing, not identity. |
| `cmd/signet-proxy/` | signet | Reverse proxy with PoP auth. |
| `cmd/signet-agent/` | signet | gRPC agent for key ops. |
| `cmd/sigstore-kms-signet/` | signet | Sigstore bridge. |

---

## Type Duplication: signet ↔ sigid

| signet Location | sigid Location | Type/Constant | Status |
|-----------------|---------------|---------------|--------|
| `cmd/signet/authority.go:531-532` (OID `{99999,1,1}`, `{99999,1,2}`) | `sigid/identity.go:37-42` (`OIDSubject`, `OIDIssuanceTime`) | X.509 extension OIDs | **Duplicated** — sigid should be canonical source |
| `cmd/signet/authority.go:482-486` (`Claims{Email,Subject,Name}`) | `sigid/context.go:12-24` (`Context{Provenance,Environment,Boundary}`) | Identity claims types | **Divergent** — authority uses flat `Claims`; sigid has richer `Context` |
| `pkg/signet/token.go` fields 14-15 (`Actor`, `Delegator`) | `sigid/context.go:27-39` (`Provenance{ActorPPID,DelegatorPPID}`) | Identity in token | **Legacy overlap** — fields 14-15 are legacy; sigid field 20 replaces them |
| `pkg/signet/capability.go` (`ComputeCapabilityID`) | `sigid/cell.go:8-11` (`PolicyStatement{Allow,Deny}`) | Capability/policy types | **Complementary** — signet has token-level caps; sigid has cell-level policy |
| `pkg/attest/x509/bridge.go:16` (`OIDSignetCapabilities`) | (not yet in sigid) | Capability cert extension OID | **Not yet duplicated** — will need to be shared |

---

## Summary: What Moves Where

### Moves to sigid

| Current Location | New Home | Notes |
|-----------------|----------|-------|
| `pkg/oidc/` (entire package) | sigid module | OIDC provider abstraction = identity verification |
| `pkg/attest/x509/` (entire package) | sigid module | LocalCA + bridge certs = identity issuance |
| `cmd/signet/authority.go` (identity portions) | sigid module | Authority server, OIDC flow, cert minting |
| `cmd/signet/auth_login.go` | sigid module | Client identity provisioning |
| `cmd/signet/auth_register.go` | sigid module | Headless identity provisioning |
| `cmd/signet/auth_status.go` | sigid module | Identity cert status |
| `cmd/signet/auth.go` | sigid module | Parent command |
| `cmd/signet/authority_exchange.go` | sigid module | Client-side OIDC exchange |
| `cmd/signet/authority_setup_resign.go` | sigid module | CI/CD identity config |

### Moves to sigpol

| Current Location | New Home | Notes |
|-----------------|----------|-------|
| `pkg/policy/evaluator.go` | sigpol module | Policy evaluation = authorization decisions |

### Stays in signet

| Package | Reason |
|---------|--------|
| `pkg/crypto/` (all) | Core crypto primitives |
| `pkg/signet/` | Token wire format |
| `pkg/http/middleware/` | Request-level PoP auth |
| `pkg/http/header/` | Wire format parsing |
| `pkg/revocation/` | CA bundle revocation |
| `pkg/collections/` | Generic data structures |
| `pkg/errors/` | Error types |
| `pkg/lifecycle/` | Memory zeroization |
| `pkg/git/` | Git signing |
| `pkg/cli/` | CLI infrastructure |
| `pkg/agent/` | gRPC agent |
| `cmd/signet/sign.go` | File signing |
| `cmd/signet/ca_bundle_server.go` | CA bundle server |
| `cmd/signet-git/` | Git integration |
| `cmd/signet-proxy/` | Auth proxy |
| `cmd/signet-agent/` | Agent binary |
| `cmd/sigstore-kms-signet/` | Sigstore bridge |

---

## Dependency Graph (Post-Move)

```
sigpol
  └── depends on: signet (capability token types from pkg/signet)
  └── depends on: sigid (claims from OIDC providers)

sigid
  └── depends on: signet (pkg/crypto/keys for key management)
  └── depends on: signet (pkg/signet/token for Token type)

signet
  └── depends on: nothing (foundational layer)
```

No circular dependencies. The dependency direction is:
```
sigpol → sigid → signet
```

This matches the data flow: policy checks identity, identity uses crypto.

---

## Key Integration Seams

1. **OIDC verify → policy evaluate → cert mint** (`authority.go:handleExchangeToken` lines 1564-1782): This is where all three components meet. sigid verifies the token, sigpol evaluates policy, sigid mints the cert.

2. **Provider.MapCapabilities()** (`pkg/oidc/provider.go:25`): Currently on the sigid `Provider` interface but conceptually sigpol's job. Short-term keep on provider; long-term, sigpol's `PolicyChecker.ResolveCapabilities()` replaces it.

3. **Token fields 14-15 ↔ field 20**: Legacy identity fields in signet tokens vs. sigid's richer provenance chain. sigid already handles the fallback (`doc.go` line 26).

4. **Capability token values**: `pkg/signet/capability.go` computes hashes (signet), but the uint64 token values come from sigpol's trust policy bundles.

5. **CA bundle ↔ policy bundle infrastructure**: `pkg/revocation/cabundle/` and the proposed `pkg/policy/{cache,checker}.go` share the same patterns (signed bundles, monotonic seqno, TTL cache, fail-closed). Consider a shared `pkg/bundle/` base if duplication becomes significant.
