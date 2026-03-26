# Edge Signing Contract: Go Authority ↔ TS Edge Worker

**Status:** Living reference document

**Date:** 2025-07-04

**Audience:** Go (signet authority) and TypeScript (rig edge worker) developers working on the certificate issuance seam.

> This document defines the contract between the Go authority (`cmd/signet/`) and the
> TypeScript edge worker (`rig/web/src/auth/signet-edge.ts`) for X.509 bridge certificate
> minting. It covers shared OIDs, encoding rules, current implementation gaps, and the
> path to closing them.

---

## OID Table

All OIDs live under the private enterprise arc `1.3.6.1.4.1.99999.1.*`.

| OID | Constant | Purpose | Go Authority | TS Edge (rig) |
|-----|----------|---------|:------------:|:--------------:|
| `1.3.6.1.4.1.99999.1.1` | `OIDSubject` | OIDC subject / user ID | ✅ raw UTF-8 | ✅ raw UTF-8 |
| `1.3.6.1.4.1.99999.1.2` | `OIDIssuanceTime` | RFC 3339 issuance timestamp | ✅ raw UTF-8 | ✅ raw UTF-8 |
| `1.3.6.1.4.1.99999.1.3` | `OIDSignetCapabilities` | Bridge cert capability attestation | ✅ ASN.1 SEQUENCE | — (bridge certs only) |
| `1.3.6.1.4.1.99999.1.5` | `OIDAgentName` | Agent identity (non-human cert) | ✅ raw UTF-8 | ❌ not implemented |
| `1.3.6.1.4.1.99999.1.6` | `OIDScope` | Agent scope restriction | ✅ raw UTF-8 | ❌ not implemented |

**Canonical source:** [`pkg/sigid/identity.go`](../../pkg/sigid/identity.go) (OID definitions + doc comments)

**Cross-repo usage:** The same OID arc is referenced in:
- `cmd/signet/authority_identity.go` — Go authority writes extensions during `mintClientCertificateWithAgent()`
- `rig/web/src/auth/signet-edge.ts` — TS edge writes `1.1` and `1.2` only
- `cmd/signet/verify.go` — `extractExtValue()` reads all four OIDs

> **Note:** The OID arc `1.3.6.1.4.1.99999` is a placeholder. A PEN (Private Enterprise Number)
> registration with IANA is required before public release. See [`integration-seams.md`](./integration-seams.md).

---

## Encoding Rules

### Writers

| Writer | Encoding | Example (for subject `"github-12345"`) |
|--------|----------|---------------------------------------|
| **Go authority** (`authority_identity.go`) | Raw UTF-8 bytes — `Value: []byte(claims.Subject)` | `67 69 74 68 75 62 2d 31 32 33 34 35` |
| **TS edge** (`signet-edge.ts` via `@peculiar/x509`) | May produce DER-encoded `UTF8String` (tag `0x0c` + length + value) | `0c 0c 67 69 74 68 75 62 2d 31 32 33 34 35` |

The Go authority uses `pkix.Extension{ Value: []byte(...) }`, which writes raw bytes directly into the extension value. The TypeScript edge uses `@peculiar/x509`, which may wrap string values in an ASN.1 `UTF8String` envelope.

### Consumer Contract

All consumers **MUST** accept both encodings. The reference implementation is `extractExtValue()` in [`cmd/signet/verify.go`](../../cmd/signet/verify.go):

```go
func extractExtValue(raw []byte) string {
    if len(raw) == 0 || len(raw) > maxExtensionValueLen {
        return ""
    }
    // Only attempt ASN.1 decode if the first byte is the UTF8String tag (0x0c).
    if raw[0] == 0x0c {
        var s string
        if rest, err := asn1.Unmarshal(raw, &s); err == nil && len(rest) == 0 {
            return s
        }
    }
    // Fallback: raw bytes as string (Go authority encoding).
    return string(raw)
}
```

**Rules:**
1. Check for ASN.1 `UTF8String` tag (`0x0c`) before attempting decode.
2. Verify DER was fully consumed (`len(rest) == 0`) to avoid misinterpreting raw bytes.
3. Fall back to raw `string(bytes)` — this is the Go authority's encoding.
4. Reject values larger than 4 KiB (`maxExtensionValueLen`).

---

## Seam Status

### Issuance Paths

| Endpoint | Runtime | Cert Type | OIDs Written | Auth Method |
|----------|---------|-----------|-------------|-------------|
| `/callback` | Go authority (Fly) | Human client cert | `1.1`, `1.2` | OAuth2 + PKCE (browser) |
| `/exchange-token` | Go authority (Fly) | CI/CD bridge cert | `1.1`, `1.2` | Ambient OIDC token (GitHub Actions, CF Access) |
| `/api/cert/register` | Go authority (Fly) | Agent client cert | `1.1`, `1.2`, `1.3`, `1.4` | GitHub PAT (`read:user`) |
| `/api/cert/register` | TS edge (rig Worker) | Human client cert | `1.1`, `1.2` | GitHub PAT |
| `/api/cert` | TS edge (rig Worker) | Human client cert | `1.1`, `1.2` | OAuth2 Bearer token |

### The Gap

When `/api/cert/register` is handled by the **rig edge worker**, the minted certificate does **not** include `OIDAgentName` (`1.3`) or `OIDScope` (`1.4`), even if the CLI sends `agent_name` and `scope` in the request body.

**Impact:** Agents registered via the rig edge path get human-equivalent certs with no scope restriction. The `--agent` and `--scope` flags in `signet auth register` are silently ignored when the request routes to the edge.

### Fix Paths

| Option | Effort | Trade-off |
|--------|--------|-----------|
| **A. Add OID writing to `signet-edge.ts`** | Low | Keeps edge-local minting; requires `@peculiar/x509` extension API and encoding parity testing |
| **B. Route agent registration through Go authority** | Low | Centralizes agent cert logic; adds a network hop (edge → Fly) for agent registrations only |
| **C. Replace TS cert minting with Wasm module** | Medium | Eliminates encoding divergence entirely; blocked on JS bindings (see below) |

**Recommendation:** Option B for immediate fix (route `/api/cert/register` with `agent_name` present to Go authority), Option C for long-term convergence.

---

## Wasm Integration Status

| Component | Status |
|-----------|--------|
| `rs/crates/sign` (Rust crate) | Builds as `wasm32-unknown-unknown` (`task rs:wasm`) |
| Crate type | `cdylib`, `staticlib`, `rlib` — Wasm-compatible |
| CMS signing | Ed25519 CMS/PKCS#7 per RFC 5652 + RFC 8419 |
| OID definitions | CMS-level only (`rs/crates/sign/src/oid.rs`) — no Signet extension OIDs yet |
| JS/TS bindings | ❌ **None exist** — no `wasm-bindgen` or `wasm-pack` integration |
| CF Worker usage | Currently uses `@peculiar/x509` (TypeScript) for all cert operations |

**Future state:** The Wasm module replaces `@peculiar/x509` for CMS signing at the edge, eliminating the encoding divergence between Go and TS. Prerequisites:

1. Add `wasm-bindgen` feature and JS bindings to `rs/crates/sign`
2. Add Signet extension OIDs (`1.3.6.1.4.1.99999.1.*`) to the Rust crate
3. Expose a `mint_bridge_cert()` function callable from the CF Worker
4. Remove `@peculiar/x509` dependency from `signet-edge.ts`

---

## Least-Privilege Agent Onboarding

Each identity class requires the minimum scopes necessary for identity verification.

| Identity Class | Auth Flow | Required Scopes | Notes |
|---------------|-----------|-----------------|-------|
| **Human** (browser OAuth) | `/callback` via OAuth2 + PKCE | `openid`, `email`, `profile` | No GitHub API scopes — identity comes from OIDC claims |
| **Agent** (headless register) | `/api/cert/register` via GitHub PAT | `read:user` only | Just enough to verify `GET /user` identity; no repo access |
| **CI/CD** (OIDC exchange) | `/exchange-token` via ambient token | Zero GitHub scopes | Uses GitHub Actions OIDC token — no PAT needed at all |

**Principle:** Certificate issuance should never require more access than identity verification demands.

**Future improvement:** Agents should receive GitHub App installation tokens (per-repo scoped) instead of inheriting the sponsoring human's PAT. This would enforce repo-level least privilege at the token layer, not just the cert extension layer.

---

## What's NOT Enforced Yet

These are known enforcement gaps in the current implementation.

| Gap | Description | Tracking |
|-----|-------------|----------|
| **Edge scope validation** | The rig edge worker does not validate `scope` claims against actual GitHub repo permissions. An agent cert could claim `repo:signet` without verification. | Requires GitHub API call during `/api/cert/register` |
| **Downstream scope enforcement** | Bridge certs carry `OIDScope` extensions, but no MCP server or middleware currently reads or enforces them. The scope is informational only. | Needs `sigid.CertIdentityProvider` integration in MCP middleware |
| **Policy bundle enforcement** | `PolicyChecker` (ADR-011) is in **bootstrap mode**: no policy bundle has been fetched, so all subjects are allowed. Bootstrap mode is permanent until a bundle server is configured. | See [`011-policy-bundles-scim.md`](./011-policy-bundles-scim.md) |
| **Revocation at edge** | The CF WAF checks `cf.tls_client_auth.cert_revoked`, but this depends on CF's CRL infrastructure. Signet's own revocation bundles (ADR-006) are not consumed at the edge. | Needs edge-side bundle fetcher |

---

## Shared Master Key

The Ed25519 master key is shared between both issuance paths so all certs chain to the same CA:

| Runtime | Key Source | Storage |
|---------|-----------|---------|
| Go authority (Fly) | `SIGNET_MASTER_KEY` env → tmpfs `/tmp/.signet/master.pem` | In-memory `ed25519.PrivateKey` for server lifetime |
| TS edge (CF Worker) | `SIGNET_MASTER_KEY` Worker secret binding | WebCrypto `CryptoKey` imported per-request |

Both produce X.509 certs with Ed25519 CA signature over ECDSA P-256 (or Ed25519) subject keys. Cert format differs slightly in CN/OU conventions:

- **Go authority:** `CN={email}, OU=Client Certificates, O=Signet Authority` (or `CN=agent:{name}, OU=Agent Certificates`)
- **TS edge:** `CN=user-{id}, O=rosary`

---

## Related Documents

- [`pkg/sigid/identity.go`](../../pkg/sigid/identity.go) — OID definitions (canonical source)
- [`cmd/signet/authority_identity.go`](../../cmd/signet/authority_identity.go) — Go authority cert minting
- [`cmd/signet/verify.go`](../../cmd/signet/verify.go) — Dual-encoding consumer (`extractExtValue`)
- [`cmd/signet/auth_register.go`](../../cmd/signet/auth_register.go) — CLI agent registration
- [`docs/design/004-bridge-certs.md`](./004-bridge-certs.md) — Bridge cert ADR (target design)
- [`docs/design/011-policy-bundles-scim.md`](./011-policy-bundles-scim.md) — Policy bundle design (ADR-011)
- [`docs/design/integration-seams.md`](./integration-seams.md) — Full seam map across the ecosystem
