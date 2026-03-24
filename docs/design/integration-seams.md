# Integration Seams: signet ecosystem

Maps every integration boundary between signet, sigid, sigpol, and their consumers (rig Worker, rosary, ley-line, CF edge). Each seam is documented with direction, protocol, discovery, classification, failure mode, data contract, and source files.

---

## 1. CF WAF --> signet CA (mTLS trust anchor)

| Field | Value |
|-------|-------|
| **Direction** | CF edge (WAF rule) validates client certs against signet's uploaded CA certificate |
| **Protocol** | X.509 certificate trust -- CF `cf.tls_client_auth.cert_verified` evaluation during WAF phase |
| **Discovery** | OpenTofu `cloudflare_mtls_certificate.signet_ca` resource uploads the PEM; WAF ruleset `mtls_enforce` references it via `depends_on`. The `signet_ca_cert` variable is set at deploy time. |
| **Classification** | **Hard** -- without this, all MCP requests to `mcp.rosary.bot` are blocked (WAF returns 403) |
| **Failure mode** | If the CA cert is not uploaded or expires, CF cannot verify any client cert. All non-landing-page requests are blocked. The landing page (`/`) is exempt per WAF expression. |
| **Data contract** | PEM-encoded X.509 CA certificate (Ed25519 self-signed). CF stores it in its trust store and uses it to verify the chain for client certs presented during TLS handshake. |
| **Source files** | `rig/tofu/modules/cloudflare/mtls.tf` (WAF rule + cert upload), `rig/tofu/variables.tf:83-87` (`signet_ca_cert` variable), `signet/pkg/attest/x509/` (LocalCA that generates the CA cert) |

**Notes**: The WAF expression is `(http.host eq "mcp.rosary.bot" and http.request.uri.path ne "/" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))`. Two cert issuance paths feed into this trust anchor: CF-managed certs (legacy `client-cert.ts`) and signet-issued bridge certs (`signet-edge.ts`). Both must chain to a CA in CF's trust store.

---

## 2. rig Worker --> signet-edge.ts (edge bridge cert minting)

| Field | Value |
|-------|-------|
| **Direction** | rig Worker (Hono routes) calls `mintBridgeCert()` in-process |
| **Protocol** | In-process TypeScript function call (same V8 isolate). Uses WebCrypto + `@peculiar/x509` for cert generation. |
| **Discovery** | Direct import: `import { mintBridgeCert } from '../auth/signet-edge'`. The master key PEM is read from the `SIGNET_MASTER_KEY` binding (CF Worker secret). |
| **Classification** | **Hard** -- this is how dashboard-authenticated users get bridge certs for MCP access |
| **Failure mode** | If `SIGNET_MASTER_KEY` is not set, cert minting returns null. If WebCrypto fails (key import error), the user gets no cert. Upstream OAuth session is unaffected. |
| **Data contract** | Input: `userId: string`, `publicKeyPem: string` (ECDSA P-256 or Ed25519 SPKI PEM), `masterKeyPem: string` (Ed25519 PKCS8 PEM). Output: `BridgeCertResult { certificate: string (PEM), expires_at: number (Unix), subject: string }`. Cert includes OID extensions `1.3.6.1.4.1.99999.1.1` (subject) and `1.3.6.1.4.1.99999.1.2` (issuance time). Validity: 24 hours. Cached in KV as `bridge-cert:{userId}`. |
| **Source files** | `rig/web/src/auth/signet-edge.ts` (mint function), `rig/web/src/auth/client-cert.ts` (legacy CF-managed cert path), `rig/web/src/routes/api.ts` (route that calls minting), `rig/web/src/env.ts:29` (`SIGNET_MASTER_KEY` binding) |

**Notes**: The edge mint path runs entirely at the CF edge -- no network call to the Fly-hosted signet authority. The master key is shared between the edge Worker and the Fly-hosted authority so both can sign certs that chain to the same CA.

---

## 3. signet CLI --> rig Worker (auth login / register)

| Field | Value |
|-------|-------|
| **Direction** | `signet auth login` (Go CLI on user's machine) calls rig Worker endpoints on `rosary.bot` |
| **Protocol** | HTTPS (OAuth2 + PKCE for login, Bearer token for register). JSON request/response bodies. |
| **Discovery** | `--endpoint` flag, default `https://rosary.bot`. OAuth authorize URL: `{endpoint}/oauth/authorize`. Token exchange: `{endpoint}/oauth/token`. Cert request: `{endpoint}/api/cert` (POST with Bearer token + public key PEM). Register: `{endpoint}/api/cert/register`. |
| **Classification** | **Hard** -- this is the primary human provisioning path for MCP client certificates |
| **Failure mode** | If the Worker is down or OAuth flow fails, the CLI prints an error and the user gets no cert. Existing certs continue to work until expiry. Renewal via refresh token (`/api/cert/renew`) degrades to full re-auth if the refresh endpoint fails. |
| **Data contract** | Login flow: OAuth2 authorization code + PKCE challenge/verifier. Cert request: `POST /api/cert` with `{ "public_key": "<PEM>" }` + `Authorization: Bearer <access_token>`. Response: `{ "certificate": "<PEM>", "expires_at": "<RFC3339>" }`. Register flow: `POST /api/cert/register` with GitHub token. CLI generates ECDSA P-256 keypair locally; private key never leaves the machine. Cert+key saved to `~/.signet/mcp/rosary/`. |
| **Source files** | `signet/cmd/signet/auth_login.go` (OAuth2+PKCE flow, cert request), `signet/cmd/signet/auth_register.go` (headless GitHub token flow), `rig/web/src/auth/oauth.ts` (Worker-side OAuth), `rig/web/src/routes/api.ts` (cert endpoints) |

---

## 4. signet authority --> PolicyChecker (in-process policy evaluation)

| Field | Value |
|-------|-------|
| **Direction** | `OIDCServer` calls `PolicyEvaluator.Evaluate()` before minting a bridge cert |
| **Protocol** | In-process Go interface call. `OIDCServer.policyEvaluator` field holds a `policy.PolicyEvaluator`. |
| **Discovery** | Hardcoded in `newOIDCServer()`: `policyEvaluator: &policy.StaticPolicyEvaluator{}`. No external config currently -- the evaluator is instantiated inline. |
| **Classification** | **Soft** -- currently a pass-through (`StaticPolicyEvaluator` with empty allowlists = allow all). Will become hard when sigpol is wired in. |
| **Failure mode** | If `Evaluate()` returns an error, the exchange-token handler returns 500. If it returns `Allowed: false`, returns 403 with generic message. Currently no deny path is exercised because the default evaluator allows everything. |
| **Data contract** | Input: `EvaluationRequest { Provider: string, Subject: string, Claims: map[string]any, RequestedCaps: []string }`. Output: `EvaluationResult { Allowed: bool, Capabilities: []string, Validity: time.Duration, Reason: string }`. The `Capabilities` list is intended to flow into cert extensions (not yet implemented). The `Validity` override lets policy shorten cert lifetime. |
| **Source files** | `signet/pkg/policy/evaluator.go` (interface + `StaticPolicyEvaluator`), `signet/cmd/signet/authority.go:757` (wiring in `newOIDCServer`), `signet/cmd/signet/authority.go:1502-1591` (`handleExchangeToken` calls policy) |

**Notes**: This is the primary seam where **sigpol** will plug in. The `StaticPolicyEvaluator` is a placeholder. The future `sigpol.PolicyChecker` will implement the same `PolicyEvaluator` interface but evaluate against compiled policy bundles instead of static allowlists.

---

## 5. signet authority --> OIDC providers (token verification)

| Field | Value |
|-------|-------|
| **Direction** | signet authority verifies incoming OIDC tokens against external identity providers |
| **Protocol** | HTTPS. OIDC discovery (`.well-known/openid-configuration`), JWKS fetch, JWT verification per RFC 7519. |
| **Discovery** | Provider config from `oidc-providers.yaml` or env vars (`SIGNET_OIDC_PROVIDERS` JSON, or `SIGNET_GITHUB_ACTIONS_ENABLED` + `SIGNET_GITHUB_ACTIONS_AUDIENCE`). Issuer URLs: GitHub Actions = `https://token.actions.githubusercontent.com`, Cloudflare Access = per-team URL. JWKS refreshed hourly via goroutine. |
| **Classification** | **Hard** -- without OIDC verification, no bridge certs can be issued for CI/CD |
| **Failure mode** | If the OIDC provider is unreachable, token verification times out (10s context deadline). JWKS refresh failure logs but keeps using the last-known-good keyset. If all providers fail, `VerifyToken` returns "no provider could verify token" and the client gets 401. |
| **Data contract** | Input: raw JWT string + optional `provider_hint`. Output: `Claims { Subject, Issuer, Audience, ExpiresAt, IssuedAt, NotBefore, Extra map }`. GitHub Actions extras: `repository`, `ref`, `workflow`, `actor`, `sha`, `run_id`. Cloudflare Access extras: `email`, `identity_nonce`, `country`. Token replay prevented via JTI cache (LRU, 10k entries). |
| **Source files** | `signet/pkg/oidc/provider.go` (Registry, BaseProvider, JWKS refresh), `signet/pkg/oidc/github.go` (GitHub Actions provider), `signet/pkg/oidc/cloudflare.go` (CF Access provider), `signet/pkg/oidc/config.go` (YAML/JSON/env loading), `signet/cmd/signet/authority.go:144-170` (registry init), `signet/cmd/signet/authority.go:1564-1582` (verify in exchange handler) |

---

## 6. rosary --> signet (agent identity for dispatched agents)

| Field | Value |
|-------|-------|
| **Direction** | rosary dispatches Claude Code agents that need MCP access; agents inherit the host's signet cert |
| **Protocol** | Filesystem-based. rosary's `ClaudeProvider` spawns `claude -p` with the host's `~/.signet/mcp/rosary/` cert+key. Claude Code reads its MCP config (set by `signet auth login --skip-configure` or `claude mcp add`) which points to the cert files. |
| **Discovery** | Agent inherits the user's `~/.claude.json` MCP config (or project-level `.mcp.json`), which references `~/.signet/mcp/rosary/cert.pem` and `key.pem`. The cert was provisioned by `signet auth login` or `signet auth register`. |
| **Classification** | **Soft** -- agents can still do local work without MCP access; MCP tools just fail gracefully |
| **Failure mode** | If no cert exists, MCP tool calls fail (mTLS handshake rejected by CF WAF). Agent continues with local tools. If cert expired, same failure. No automatic renewal during dispatch -- the user must have a valid cert before dispatching. |
| **Data contract** | The cert is a standard X.509 client certificate (ECDSA P-256 subject key, Ed25519 CA signature). CN=`user-{githubId}` or `email@example.com`. Carries OID extensions for subject identity and issuance time. The private key is PKCS8 PEM. |
| **Source files** | `rosary/src/dispatch/providers.rs` (ClaudeProvider spawns agent), `signet/cmd/signet/auth_login.go:571-586` (`configureClaude` writes MCP config), `signet/cmd/signet/auth_login.go:530-569` (`saveCertBundle` writes cert+key+metadata) |

**Notes**: This is currently implicit -- rosary doesn't explicitly manage signet identity. A dispatched agent simply uses whatever cert the host user provisioned. Future work: rosary could request scoped certs for agents (per-bead identity), or `signet auth register` could be called during dispatch setup.

---

## 7. ley-line --> signet (manifest signing)

| Field | Value |
|-------|-------|
| **Direction** | ley-line uses Ed25519 CMS/PKCS#7 signing with signet-issued certificates |
| **Protocol** | In-process Rust library call. `leyline-sign` crate provides `cms::sign_data()` and `cms::verify_signature()`. The `leyline-sign` binary is a gpgsm-compatible CLI for jj commit signing. |
| **Discovery** | Build-time dependency: `leyline-sign` crate in `ley-line/rs/crates/sign/`. Certificate and key paths are passed as CLI args or loaded from config. The signing cert is expected to be a signet-issued Ed25519 cert. |
| **Classification** | **Build-time / optional** -- ley-line can operate without signing; signing adds integrity guarantees to manifests |
| **Failure mode** | If no cert/key available, signing is skipped (unsigned manifests). Verification fails with `VerifyError::InvalidSignature` if the cert doesn't match the key or the signature is invalid. Key mismatch caught by `cert::verify_key_match()`. |
| **Data contract** | `sign_data(data: &[u8], cert_der: &[u8], private_key: &[u8; 64]) -> Vec<u8>` returns DER-encoded CMS ContentInfo (RFC 5652). Signed attributes: contentType (id-data), messageDigest (SHA-512), signingTime (UTCTime). SignerIdentifier: issuerAndSerialNumber from cert. Verification: `verify_signature(data, signature_der, cert_der) -> bool`. |
| **Source files** | `ley-line/rs/crates/sign/src/cms.rs` (CMS sign/verify), `ley-line/rs/crates/sign/src/cert.rs` (cert parsing, key match), `ley-line/rs/crates/sign/src/oid.rs` (OID constants), `signet/rs/crates/sign/` (parallel Rust implementation in signet repo) |

**Notes**: Both signet and ley-line have their own `sign` crate. The ley-line crate is the operational one (used by `leyline-sign` binary for jj commit signing). The signet crate (`rs/crates/sign/`) is the reference implementation with FFI and Wasm targets. They share the same CMS format and OIDs but are not yet deduplicated.

---

## 8. sigid CertProvider --> CF tlsClientAuth (edge identity extraction)

| Field | Value |
|-------|-------|
| **Direction** | rig Worker reads CF-injected headers from the TLS handshake, then sigid's `cert.Provider` parses the cert |
| **Protocol** | CF injects `Cf-Client-Cert-Subject-Dn` (and other `Cf-Client-Cert-*` headers) after mTLS validation. The Worker's `identity.ts` parses the DN. For full cert parsing (Go side), sigid's `cert.Provider.ExtractIdentity()` takes an `*x509.Certificate`. |
| **Discovery** | CF headers are always present when mTLS is configured for the hostname. The Worker reads `Cf-Client-Cert-Subject-Dn` from `c.req.raw.headers`. On the Go side, the cert is available from the TLS connection state. |
| **Classification** | **Hard** for MCP auth -- the identity middleware returns null (401) if no cert headers are present |
| **Failure mode** | If CF doesn't inject cert headers (mTLS not configured or cert not presented), `extractIdentity()` returns null. The `identityMiddleware` falls through to Bearer token auth. If that also fails, the request is unauthenticated. |
| **Data contract** | CF header: `Cf-Client-Cert-Subject-Dn` = `CN=user-{id},O=rosary`. Worker parses CN prefix: `user-*` -> `IdentityType='user'`, `service-*` -> `IdentityType='machine'`. sigid `cert.Provider` extracts: `Identity { Owner (from OID 1.3.6.1.4.1.99999.1.1 or CN fallback), Machine (SHA-256 of SPKI public key), Issuer (cert issuer CN), IssuedAt, ExpiresAt, Raw *x509.Certificate }`. Also extracts `Context { Provenance { ActorPPID, Issuer } }`. |
| **Source files** | `rig/web/src/auth/identity.ts` (Worker-side DN parsing), `rig/web/src/middleware/identity.ts` (identity middleware), `sigid/providers/cert/provider.go` (Go-side cert extraction), `sigid/identity.go` (Identity type + CertIdentityProvider interface), `sigid/context.go` (Context type) |

**Notes**: There are two extraction paths: (1) Edge/Worker uses string parsing of CF-injected headers (lightweight, TS), (2) Go-side uses full X.509 parsing via sigid's `cert.Provider` (rich, typed). The OID extensions (`1.3.6.1.4.1.99999.1.1`, `1.3.6.1.4.1.99999.1.2`) are shared across signet authority (Go), signet-edge.ts (TS), and sigid cert provider (Go).

---

## 9. sigpol PolicyChecker --> bundle distribution (CA bundle infrastructure)

| Field | Value |
|-------|-------|
| **Direction** | Policy checkers fetch compiled policy bundles from a distribution endpoint, mirroring the CA bundle pattern |
| **Protocol** | HTTPS fetch + CBOR-encoded signed bundles (same model as `revocation.CABundleChecker`) |
| **Discovery** | Fetcher interface: `types.Fetcher.Fetch(ctx, issuerID) -> *CABundle`. For revocation, the fetcher is injected at construction. The same pattern applies to policy bundles -- a `PolicyBundleFetcher` would fetch from a well-known endpoint or local file. |
| **Classification** | **Soft** -- policy evaluation is currently a no-op (allow-all). When sigpol is wired, it becomes hard for restricted environments. |
| **Failure mode** | `CABundleChecker` fails closed: if fetch fails, `IsRevoked` returns an error (not "allow"). Bundle signature verification prevents fake bundles. Monotonic sequence number prevents rollback. Max bundle age (1 hour) prevents stale bundles. The same fail-closed, signature-verified, rollback-protected model should apply to policy bundles. |
| **Data contract** | CA bundle: `CABundle { Epoch uint64, Seqno uint64, Keys map[string][]byte, KeyID string, PrevKeyID string, IssuedAt int64, Signature []byte }`. Encoded as CBOR with canonical encoding for deterministic signatures. Verified via `algorithm.Verify(trustAnchor, canonical, signature)`. Policy bundles (future) would follow the same shape: epoch, seqno, policy rules, signature. Storage: `types.Storage` interface with atomic `SetLastSeenSeqnoIfGreater` for rollback protection. |
| **Source files** | `signet/pkg/revocation/checker.go` (CABundleChecker -- the pattern sigpol mirrors), `signet/pkg/revocation/types/types.go` (CABundle, Fetcher, Storage interfaces), `signet/pkg/revocation/cabundle/` (BundleCache), `signet/pkg/policy/evaluator.go` (current PolicyEvaluator -- will be replaced by bundle-backed evaluator) |

**Notes**: The CA bundle infrastructure in `pkg/revocation/` is the reference pattern for all signed bundle distribution in the ecosystem. sigpol will reuse the same primitives: CBOR canonical encoding, Ed25519/ML-DSA signature verification, monotonic sequence numbers, and fail-closed semantics. The `Fetcher` and `Storage` interfaces are generic enough to serve both revocation and policy bundles.

---

## Seam dependency graph

```
                              OIDC Providers
                              (GitHub Actions,
                               CF Access, Clerk)
                                    |
                                    v
 signet CLI ----HTTPS----> rig Worker ----in-process----> signet-edge.ts
 (auth login)              (rosary.bot)                   (mintBridgeCert)
      |                         |                               |
      |                    CF WAF rule <---- signet CA cert -----|
      |                    (mTLS enforce)   (tofu upload)
      |                         |
      |                         v
      |              CF tlsClientAuth headers
      |                         |
      |                         v
      |              rig identity middleware
      |              (identity.ts / sigid)
      |                         |
      v                         v
 ~/.signet/mcp/         signet authority (Fly :8081)
 (cert + key)           /exchange-token
      |                    |           |
      |                    v           v
      |             OIDC Registry   PolicyEvaluator
      |                              (sigpol future)
      |                                    |
      v                                    v
   rosary                         Bundle distribution
   (dispatch)                     (CA bundles / policy bundles)
      |
      v
   ley-line
   (manifest signing)
```

---

## Cross-cutting concerns

### Shared OIDs
The private enterprise OID arc `1.3.6.1.4.1.99999.1.*` is used across three codebases:
- `1.3.6.1.4.1.99999.1.1` -- Subject identity (OIDC sub / user ID)
- `1.3.6.1.4.1.99999.1.2` -- Issuance time (RFC3339)

Defined in: `signet/cmd/signet/authority.go:527-538`, `rig/web/src/auth/signet-edge.ts:20-21`, `sigid/providers/cert/provider.go:22-25`, `sigid/identity.go:37-42`.

### Shared master key
The Ed25519 master key is shared between the Fly-hosted signet authority and the CF Worker (edge mint). Both sign bridge certs. The key is provisioned as:
- Fly secret `SIGNET_MASTER_KEY` (written to tmpfs at `/tmp/.signet/master.pem`)
- CF Worker secret binding `SIGNET_MASTER_KEY`

### Certificate format parity
Both the Go authority and the TS edge minter produce X.509 bridge certs with:
- `CN=user-{id},O=rosary` (edge) or `CN={email},OU=Client Certificates,O=Signet Authority` (Go authority)
- Same OID extensions
- Ed25519 CA signature (authority key) over ECDSA P-256 or Ed25519 subject key

### Auth routing
- `mcp.rosary.bot` -> CF tunnel -> Fly `:8080` (rsry MCP server, mTLS enforced by WAF)
- `auth.rosary.bot` -> CF tunnel -> Fly `:8081` (signet authority, no mTLS, handles own OIDC auth)
- `rosary.bot` -> CF Worker (dashboard, OAuth, `/api/cert` endpoints)
