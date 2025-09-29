# Signet: Fixing Authentication's Fundamental Flaw

## The Problem

**Bearer tokens are inherently insecure.** If someone steals your JWT, OAuth token, or API key, they can use it immediately from anywhere. This is authentication's original sin - possession equals identity.

Current "solutions" don't solve the problem:
- **MFA** only protects initial login, not token usage after theft
- **Token rotation** shortens the theft window but doesn't eliminate it
- **Zero Trust** just verifies stolen tokens more frequently
- **mTLS** works but is operationally complex and inflexible

Every major breach involves stolen tokens. SolarWinds, Okta, Microsoft - attackers steal tokens and become indistinguishable from legitimate users.

## The Solution

**Signet replaces bearer tokens with proof-of-possession (PoP) tokens.** Stolen tokens become useless without the corresponding private key.

### How It Works

1. **Token includes key binding**: The Signet token contains a hash of the public key (`cnf_key_hash`)
2. **Every request carries proof**: Client signs each request with the private key
3. **Server verifies possession**: Signature proves the caller has the private key

```
Traditional Bearer:
Authorization: Bearer <token anyone can use>

Signet PoP:
Authorization: SIG1.<token>
Signet-Proof: v=1; sig=<signature only key holder can create>
```

### Additional Improvements

- **Semantic capabilities**: `["read", "env:prod"]` instead of opaque permission strings
- **Instant revocation**: Epoch-based snapshots, not waiting for token expiry
- **Smaller tokens**: CBOR encoding (~250 bytes vs ~1KB for JWTs)
- **Privacy preserving**: Per-token pseudonyms prevent correlation

## Implementation Simplicity

**For Developers:**
```bash
# One-time setup
$ signet login

# Automatic PoP on every request
$ signet api get /users  # SDK handles signing
```

**For Services:**
```python
# Add one check
if not verify_pop(request.headers["Signet-Proof"], token):
    return 401
```

## Migration Path

1. **Phase 1**: OAuth/JWT wrapper generates Signet tokens - no client changes
2. **Phase 2**: Clients adopt SDK - services accept both tokens
3. **Phase 3**: Services require PoP - full security benefits

## Why This Matters

Current authentication is like using physical keys that can be copied. Signet makes tokens like contactless car keys - possession isn't enough, you need the cryptographic fob.

This isn't a marginal improvement. It's fixing the fundamental vulnerability that enables most security breaches.

## Deployment Requirements

- **Issuer service**: Mints CBOR tokens with capability management
- **Client SDKs**: Handle key management and request signing
- **Verification library**: Services verify PoP signatures
- **Snapshot distribution**: CDN or simple HTTP for revocation epochs

No blockchain. No complex infrastructure. Just cryptographic proof on every request.

---

**Bottom line**: Bearer tokens are broken. Signet fixes them with proof-of-possession while keeping the developer experience simple.
