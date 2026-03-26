# Revocation Strategy

**Status**: Partially Implemented (core in `pkg/revocation/`, `pkg/revocation/cabundle/`; deployment checklist items below remain open)
**Date**: 2025-10-05

---

## System Overview

```
┌─────────────────────────────────────────────┐
│ CA Bundle Distribution (Revocation System)  │
└─────────────────────────────────────────────┘

Verifier --[mTLS + bridge cert]--> CA Bundle Server
         <--[CA bundle: kid, epoch, seqno, pubkey]--

┌─────────────────────────────────────────────┐
│ Token Verification (Using CA Bundle)        │
└─────────────────────────────────────────────┘

Client --> Token + ephemeral cert --> Verifier
                                         │
                                         ├─ Check cert signed by CA bundle pubkey
                                         ├─ Check epoch not revoked
                                         ├─ Check kid matches
                                         └─ ✓ Accept / ✗ Reject
```

**Key Insight**: Bridge certificates secure the distribution channel. CA bundle provides validation keys. Monotonic seqno prevents rollback.

---

## Executive Summary

**Decision**: Adopt the SPIRE Model for v1.0 revocation - short-lived certificates (5-minute TTL) with CA bundle rotation via local mTLS-DNS or HTTPS with certificate pinning.

**Rationale**:
- ✅ **Production-proven**: Kubernetes SPIRE, Google ALTS, Azure AD PoP all use this model at planet-scale
- ✅ **Simple**: 1/10th the complexity of snapshot-based revocation systems
- ✅ **Fast to ship**: Production-ready in 1 week vs 6-8 weeks for granular revocation
- ✅ **Offline-first**: Zero dependency on external infrastructure for core operations
- ✅ **Sufficient for v1.0**: 5-7 minute revocation SLA meets vast majority of use cases

**Trade-off**: Cannot revoke individual tokens before certificate expiry (5 min max). This is acceptable for v1.0; granular revocation can be added in future if needed.

---

## Context

Signet uses ephemeral proof-of-possession with short-lived certificates for authentication. Unlike bearer tokens, certificates have embedded expiry, but we need a mechanism to revoke certificates before expiry in case of compromise.

### Requirements

**Must Have (v1.0)**:
- Immediate CA key rotation (if issuer private key compromised)
- Offline-first operation (no dependency on CDN, OCSP, or external services)
- Bounded staleness guarantee (maximum revocation latency is provable)
- Cryptographically sound rollback protection

**Nice to Have (Future)**:
- Individual token revocation before expiry (<5 min granularity)
- Privacy-preserving revocation checks (no token ID leakage)

---

## Threat Model

### Attacker Capabilities

This revocation system defends against:

1. **Network-Level Attackers (MITM)**:
   - Can intercept and modify network traffic
   - Can replay old, valid messages
   - **Defense**: mTLS-secured channel with monotonic sequence numbers

2. **Compromised Individual Tokens**:
   - Attacker obtains a valid token/certificate
   - Wants to use it after legitimate revocation
   - **Defense**: Certificate expiry (5-minute TTL) + CA rotation

3. **Compromised CA Private Key**:
   - Attacker obtains issuer's CA signing key
   - Can mint arbitrary valid certificates
   - **Defense**: CA key rotation + epoch bump + kid mismatch rejection

4. **Rollback Attacks**:
   - Attacker serves old but validly-signed CA bundles
   - Attempts to "un-revoke" tokens by reverting to earlier state
   - **Defense**: Monotonic sequence numbers with persistent storage

### Explicitly Out-of-Scope

v1.0 **does not** defend against:

- **Sub-5-Minute Individual Token Revocation**: Once certificate issued, valid until expiry. Acceptable trade-off for v1.0.
- **Offline Verifier Compromise**: If attacker controls verifier's persistent storage, they could manipulate sequence numbers. Mitigation: Use tamper-evident storage (TPM/OS Keychain).
- **DNS Infrastructure Compromise**: If local mTLS-DNS server compromised, attackers could serve malicious bundles. Mitigation: Proper operational security.

### Threat Coverage

| Threat | v1.0 Defense |
|--------|--------------|
| MITM / Network Attacks | ✅ mTLS-secured channel |
| Individual Token Compromise | ⚠️ 5-7 min expiry window |
| CA Key Compromise | ✅ <1 min rotation |
| Rollback Attacks | ✅ Monotonic seqno |
| Timing/Side-Channel | ✅ Encrypted queries |

---

## Bridge Certificates (004-bridge-certs.md Summary)

Bridge certificates enable **offline-first mutual authentication** for both distribution mechanisms (mTLS-DNS and HTTPS+pinning).

### What is a Bridge Certificate?

A bridge certificate is a **pre-provisioned X.509 client certificate** that allows a verifier to authenticate to the CA bundle server without online verification.

**Key Properties**:
- **Issued once**: During verifier provisioning (offline or during setup)
- **Short-to-medium lived**: Typical 90-day TTL with automated renewal at 60-day mark
- **Mutual authentication**: Server verifies client cert, client verifies server (via pin or CA)
- **Offline operation**: No OCSP, CRL, or online revocation checks required

**Operational Note**: Alert if renewal fails at 30-day mark; document manual renewal procedure for emergency.

### Usage in Revocation System

```go
// Verifier uses bridge cert to authenticate to local CA bundle server
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            Certificates: []tls.Certificate{bridgeCert},  // Client auth
            // Server auth via pinning or trusted CA
        },
    },
}
```

**Benefits**:
- Both mTLS-DNS and HTTPS+pinning use same bridge cert mechanism
- Full security equivalence between distribution methods
- No online dependency for authentication

---

## Decision: SPIRE Model

### How It Works

**Instead of maintaining revocation lists**, rely on:

1. **Short-lived certificates** (5 minutes): Tokens expire quickly, limiting compromise window
2. **CA bundle rotation**: When CA key compromised, rotate key and distribute new bundle
3. **Epoch-based versioning**: Embed `kid` (key ID) and `epoch` in tokens
4. **Fail-closed on mismatch**: Reject any token with unknown `kid` or old `epoch`

### CA Bundle Distribution

**CA Bundle Structure** (DNS TXT or JSON):
```
v=sig1;kid=2025-10-05a;pk=<ed25519-public-key>;epoch=1;seqno=12345
```

**Two Implementation Options**:

**Option A: mTLS-DNS** (Recommended for network deployment)
- Local DNS server (CoreDNS) on port 853 (DNS-over-TLS)
- Verifier queries `_signet-ca.example.com` TXT record
- Mutual authentication via bridge certificates
- Sub-millisecond latency (local query)

**Option B: HTTPS with Certificate Pinning** (Recommended for initial deployment)
- Local HTTPS server on port 8443
- Verifier fetches JSON from `https://127.0.0.1:8443/ca-bundle`
- Server auth via pinned certificate SHA-256 (see operational runbook for pin rotation)
- Client auth via bridge certificate
- Simpler operational model, better tooling

### Bounded Staleness Guarantee

The maximum revocation latency is:

```
Revocation_Latency ≤ cert_ttl + verifier_cache_ttl + DNS_TTL + 2*max_clock_skew
```

**Default Values**:
- `cert_ttl` = 300s (5 minutes)
- `verifier_cache_ttl` = 30s
- `DNS_TTL` = 30s
- `max_clock_skew` = 60s (offline-first environments)

**Maximum Latency**: 300 + 30 + 30 + 120 = **480 seconds (8 minutes)**

**Note**: The `2*max_clock_skew` accounts for worst case: issuer clock -60s and verifier clock +60s.

### Rollback Protection

**Monotonic Sequence Numbers**:
- Each CA bundle includes `seqno` (strictly increasing)
- Verifier persists `last_seen_seqno` to tamper-evident storage (OS Keychain, TPM)
- Reject any bundle with `seqno ≤ last_seen_seqno`

**Storage Integrity**:
```go
// Store: seqno || HMAC(device_key, "signet-seqno-v1" || seqno)
// Device key derived via HKDF from machine-id or TPM-sealed key
```

This prevents:
- Rollback attacks (attacker serving old bundles)
- Storage corruption DoS (attacker corrupting seqno value)

### Fail-Closed Policies

Verifiers **MUST** fail-closed if:
1. CA bundle age exceeds 2x cache TTL (too stale)
2. Persistent storage unavailable or corrupted
3. seqno rollback detected
4. Bridge certificate expired and no renewal available

**Rationale**: Better to deny service than accept potentially revoked tokens.

---

## Decision Tree for Operators

```
┌─────────────────────────────────────┐
│ Deploying Signet Revocation System  │
└──────────────┬──────────────────────┘
               │
               ▼
        ┌──────────────┐
        │ Deployment   │
        │ Environment? │
        └──────┬───────┘
               │
       ┌───────┴────────┐
       │                │
   Localhost       Network
   (127.0.0.1)     (multi-host)
       │                │
       ▼                ▼
   ┌─────────┐    ┌──────────┐
   │ HTTPS + │    │mTLS-DNS  │
   │ Pinning │    │(CoreDNS) │
   └────┬────┘    └────┬─────┘
        │              │
        ▼              ▼
   Simple ops    Sub-ms latency
   Better tools  Client auth required
        │              │
        └──────┬───────┘
               ▼
      ┌────────────────┐
      │ Both use:      │
      │ - Bridge certs │
      │ - Seqno check  │
      │ - Fail-closed  │
      └────────────────┘
```

**Recommendation**: Start with **HTTPS + Pinning + Bridge Cert** for simplicity. Migrate to mTLS-DNS if you need sub-millisecond performance or network deployment requires stronger client authentication.

---

## Revocation SLAs

### Individual Token/Device Revocation
- **Method**: Issuer stops minting new tokens
- **Target SLA**: Maximum 8 minutes (cert TTL + cache staleness + clock skew)
- **Use Case**: Lost device, stolen credentials

### Master Key Compromise
- **Method**: CA key rotation + epoch bump + kid mismatch
- **Target SLA**: <1 minute (local distribution propagation)
- **Use Case**: Issuer private key leak

**Note**: These are target SLAs to validate during implementation. Actual latency depends on deployment configuration and network conditions.

**Key Insight**: Short-lived certificates (5 min) make per-token revocation lists unnecessary. This aligns with production systems at scale (Kubernetes SPIRE, Google ALTS).

---

## Consequences

### Positive

1. **Simple**: No CDN, no snapshots, no Bloom filters - just CA bundle rotation
2. **Fast to ship**: Production-ready in 1 week (vs 6-8 weeks for granular revocation)
3. **Proven at scale**: Same model as SPIRE (100M+ workloads), ALTS (all Google services)
4. **Offline-first**: Zero dependency on external infrastructure
5. **Security-equivalent options**: mTLS-DNS and HTTPS+pinning both use bridge certs

### Negative

1. **No sub-5-minute granular revocation**: Cannot revoke individual token before cert expiry
2. **Operational overhead**: Must manage local CA bundle server (DNS or HTTPS)
3. **Bridge cert management**: Automated renewal required (90-day TTL)
4. **Clock skew impact**: Offline environments can have ±60s drift, extending latency window

### Mitigations

- **For granular revocation**: Snapshot-based system available as future enhancement if users demand <5min SLA
- **For operational overhead**: Reference implementation and runbooks to be developed
- **For bridge cert renewal**: Automated renewal with alerting (details TBD during implementation)
- **For clock skew**: 5x safety margin between cert TTL and max clock skew (300s / 60s)

---

## Alternatives Considered

### Alternative 1: Snapshot-Based Revocation (CRL-style)

**Approach**: Maintain signed snapshots of revoked token JTIs, distribute via CDN, use Bloom filters for O(1) lookup.

**Rejected because**:
- 6-8 weeks to production (vs 1 week for SPIRE model)
- High infrastructure complexity (CDN, Bloom filters, snapshot signing)
- Introduces online dependency (CDN uptime required)
- Over-engineered for v1.0 use cases

**Future consideration**: Implement as "Path B" if users demand <5min granular revocation SLA.

### Alternative 2: OCSP Stapling

**Approach**: Verifiers query OCSP responder for certificate status.

**Rejected because**:
- Breaks offline-first requirement (OCSP responder must be online)
- Privacy concerns (OCSP queries leak token usage patterns)
- Performance overhead (OCSP query per verification)
- Not aligned with ephemeral certificate model

### Alternative 3: Zero-Knowledge Revocation

**Approach**: Use cryptographic accumulators or ZK-SNARKs for privacy-preserving revocation.

**Rejected because**:
- Immature tooling and standards
- Performance overhead (ZK proofs are slow on mobile)
- Complexity far exceeds v1.0 requirements
- Can revisit post-v1.0 as research area

---

## Implementation Checklist

**Week 1: Core Infrastructure**
- [ ] Create CA bundle structure with `seqno` field
- [ ] Implement DNS TXT parser OR HTTPS JSON endpoint
- [ ] Add bundle caching with 30s TTL
- [ ] Implement monotonic seqno check (reject `seqno ≤ last_seen`)
- [ ] Add persistent storage with HMAC integrity protection
- [ ] Provision bridge certificates (90-day TTL, auto-renew at 60 days)
- [ ] Configure local mTLS-DNS (CoreDNS) OR HTTPS server with pinning

**Week 1: Verifier Integration**
- [ ] Update middleware to fetch CA bundle
- [ ] Add epoch checking (reject if `token.epoch < bundle.epoch`)
- [ ] Embed `kid` in tokens for cryptographic instant-death on rotation
- [ ] Implement fail-closed policies (stale bundle, missing storage, rollback)

**Week 1: Testing & Documentation**
- [ ] Integration tests (CA rotation, seqno rollback, fail-closed scenarios)
- [ ] Performance benchmarks (establish baseline and targets)
- [ ] Basic operator documentation (CA rotation procedure, troubleshooting)
- [ ] Update 001-signet-tokens.md with revocation approach

---

## Success Criteria

v1.0 is **production-ready** when:

✅ CA key rotation propagates and invalidates old tokens
✅ Certificate expiry causes rejection (bounded staleness validated)
✅ Monotonic seqno prevents rollback attacks (tested)
✅ Storage integrity (HMAC) prevents corruption
✅ Bridge certificate auth works offline
✅ Fail-closed policies prevent security bypasses
✅ Performance benchmarks establish acceptable latency
✅ Integration tests pass (rotation, rollback, fail-closed scenarios)

---

## References

- [SPIRE Architecture](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [Google ALTS](https://cloud.google.com/security/encryption-in-transit/application-layer-transport-security)
- [001-signet-tokens.md](./001-signet-tokens.md): Signet Token Format
- [002-protocol-spec.md](./002-protocol-spec.md): Protocol Specification
- [004-bridge-certs.md](./004-bridge-certs.md): Bridge Certificates (full spec)

---

**Decision**: Adopt SPIRE Model for v1.0. Ship simple, proven solution this week. Add complexity only when scale demands it.
