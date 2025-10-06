# Signet Protocol Specification v1.0

**Status:** Draft

**Date:** 2025-09-27

**Authors:** James Gardner / @jamestexas

## Abstract

Signet is a proof-of-possession authentication protocol that replaces bearer tokens with cryptographically bound credentials. This document specifies the wire format, cryptographic operations, and verification requirements for Signet v1.0.

## 1. Protocol Overview

Signet provides:

- **Proof-of-Possession (PoP)**: Token usage requires proving possession of a private key
- **Semantic Capabilities**: Human-readable permissions encoded as compact identifiers
- **Efficient Revocation**: Epoch-based revocation with deterministic propagation
- **Privacy Preservation**: Unlinkable per-token identifiers

## 2. Wire Format

### 2.1 Token Format

```
SIG1.<base64url(CBOR payload)>.<base64url(COSE_Sign1 signature)>
```

- **Prefix**: `SIG1` identifies protocol version
- **Payload**: CBOR-encoded map with defined keys
- **Signature**: COSE_Sign1 structure with Ed25519

### 2.2 CBOR Payload Schema

```cddl
signet-token = {
  1: uint,           ; iss_id - Issuer identifier
  2: uint,           ; aud_id - Audience identifier
  3: bstr .size 32,  ; sub_ppid - Per-token pairwise pseudonym
  4: uint,           ; exp - Expiration (Unix timestamp)
  ? 5: uint,         ; nbf - Not before
  ? 6: uint,         ; iat - Issued at
  7: bstr .size 16,  ; cap_id - 128-bit capability hash
  8: uint,           ; cap_ver - Capability version (major.minor)
  9: bstr .size 32,  ; cnf_key_hash - SHA-256 of bound public key
  10: uint,          ; kid - Issuer's key ID
  11: [* uint],      ; cap_tokens - Capability list (max 32)
  ? 12: {* any},     ; cap_custom - Custom claims
  13: bstr .size 16, ; jti - Token ID
  ? 14: actor,       ; act - Actor (impersonation)
  ? 15: delegator,   ; del - Delegator (delegation)
  ? 16: text         ; aud - Audience string (debugging)
}
```

### 2.3 Canonical Encoding

All CBOR maps MUST use canonical encoding (RFC 8949 Section 4.2):

- Integer keys in ascending order
- Minimal integer encoding
- No duplicate keys

## 3. Cryptographic Operations

### 3.1 Capability Computation

```python
def compute_capability_id(cap_tokens: List[int]) -> bytes:
    """Compute 128-bit capability identifier"""
    # Sort tokens numerically
    canonical = sorted(set(cap_tokens))
    # Encode as CBOR array
    cbor_data = cbor.encode(canonical)
    # Hash and truncate
    hash_value = sha256(cbor_data).digest()
    return hash_value[:16]  # 128 bits
```

### 3.2 Pairwise Identifier Generation

```python
def generate_ppid(user_id: str, audience: str, jti: bytes, secret: bytes) -> bytes:
    """Generate unlinkable per-token identifier"""
    data = user_id.encode() + audience.encode() + jti
    return hmac_sha256(secret, data)
```

### 3.3 Proof-of-Possession

#### Request Signing

```
Signet-Proof: v=1; ts=<timestamp>; nonce=<base64url(16 bytes)>;
              kid=<ephemeral_key_id>; sig=<base64url(signature)>
```

#### Canonical String Construction

```python
def build_canonical_string(method, path, host, timestamp, nonce, jti, body=None):
    parts = [method, path, host, str(timestamp), nonce, jti]
    if method in ["POST", "PUT", "PATCH"] and body:
        parts.append(sha256(body).hexdigest())
    return "\n".join(parts)
```

#### Signature Generation

```python
def generate_proof(request, private_key, jti):
    timestamp = int(time.time())
    nonce = os.urandom(16)

    canonical = build_canonical_string(
        request.method,
        request.path,
        request.host,
        timestamp,
        base64url_encode(nonce),
        base64url_encode(jti),
        request.body
    )

    signature = ed25519_sign(private_key, canonical.encode())
    return format_proof_header(timestamp, nonce, kid, signature)
```

## 4. Verification Requirements

### 4.1 Token Verification

1. **Structure**: Validate `SIG1.payload.signature` format
1. **CBOR**: Decode and validate schema compliance
1. **Signature**: Verify COSE_Sign1 with issuer’s public key
1. **Expiration**: Ensure `current_time < exp`
1. **Audience**: Verify `aud_id` matches verifier

### 4.2 Proof-of-Possession Verification

1. **Key Binding**: Verify `kid` maps to token’s `cnf_key_hash`
1. **Timestamp**: Ensure `|current_time - ts| < max_skew` (default 60s)
1. **Nonce**: Check nonce not seen for this `jti` within time window
1. **Signature**: Verify signature over canonical string

### 4.3 Capability Verification

1. **Hash Verification**: Recompute `cap_id` from `cap_tokens`
1. **Version Check**: Ensure capability version is current
1. **Custom Claims**: Evaluate any `cap_custom` constraints

## 5. Revocation Mechanism

### 5.1 Epoch Structure

```json
{
  "iss_id": 1,
  "major_epoch": 1000,  // Revocations
  "minor_epoch": 2500,  // Capability updates
  "issued_at": 1700000000,
  "caps": [
    {"cap_id": "...", "state": "revoked", "epoch": 999}
  ],
  "signature": "..."
}
```

### 5.2 Freshness Requirements

Verifiers MUST have epoch snapshot where:

- `major_epoch >= token.cap_ver >> 16`, OR
- Within grace period (300s) AND token TTL ≤ 300s

## 6. Capability Registry

### 6.1 Standard Ranges

|Range        |Purpose    |Example                  |
|-------------|-----------|-------------------------|
|0x0001-0x00FF|Actions    |`read=0x01`, `write=0x02`|
|0x0100-0x01FF|Resources  |`env:prod=0x0100`        |
|0x0200-0x02FF|Constraints|`limit:100=0x0200`       |
|0x0300-0x03FF|Special    |`impersonate=0x0300`     |
|0x0400-0xFFFF|Reserved   |Future use               |

### 6.2 Custom Capabilities

Custom capabilities MUST be pre-registered to prevent collisions:

```python
def register_custom_capability(name: str) -> int:
    """Register custom capability with issuer"""
    if not name.startswith(org_prefix):
        raise ValueError("Must use org prefix")

    # Deterministic assignment
    hash_value = sha256(name.encode()).digest()
    capability_id = 0x10000 | (int.from_bytes(hash_value[:2], 'big'))

    registry[capability_id] = name
    return capability_id
```

## 7. Privacy Properties

### 7.1 Unlinkability

- Per-token ppids prevent correlation across tokens
- Ephemeral key IDs prevent key tracking
- No global user identifiers in tokens

### 7.2 Minimal Disclosure

- Capabilities encoded as integers (not strings)
- Custom claims optional and service-specific
- Audience string only for debugging

## 8. Security Considerations

### 8.1 Collision Resistance

128-bit capability IDs provide 2^64 collision resistance, sufficient against:

- Birthday attacks up to 2^64 capabilities
- Targeted collisions requiring 2^128 operations

### 8.2 Replay Prevention

- Per-request nonces prevent replay within time window
- Token expiration bounds maximum replay window
- JTI tracking prevents cross-service replay

### 8.3 Algorithm Agility

COSE framework allows algorithm migration:

- Current: Ed25519 (EdDSA)
- Future: Dilithium (post-quantum)

## 9. Performance Targets

|Operation         |Target |Maximum|
|------------------|-------|-------|
|Token verification|< 1ms  |5ms    |
|PoP generation    |< 2ms  |10ms   |
|PoP verification  |< 1ms  |5ms    |
|Capability lookup |< 0.1ms|1ms    |
|Token size        |< 250B |300B   |

## 10. Extensibility

### 10.1 Version Negotiation

Future versions indicated by prefix:

- `SIG1`: Version 1.0
- `SIG2`: Version 2.0 (future)

### 10.2 Custom Claims

Services MAY add custom claims (key 12) following:

- Use string keys for clarity
- Include version indicators
- Document in service specification

### 10.3 Alternative Bindings

Future specifications may define:

- WebAuthn binding for browser contexts
- TPM binding for hardware attestation
- HSM binding for high-security environments

## 11. Compliance

This protocol addresses:

- **NIST 800-63B**: AAL3 via proof-of-possession
- **GDPR Article 25**: Privacy by design via ppids
- **FIDO2 Principles**: Phishing resistance via PoP

## 12. Test Vectors

### 12.1 Example Token

```
Input:
  iss_id: 1
  aud_id: 2
  sub_ppid: <32 bytes>
  exp: 1700001000
  cap_id: <16 bytes>
  cap_ver: 65537 (v1.1)
  cnf_key_hash: <32 bytes>
  kid: 42
  cap_tokens: [1, 256, 512]
  jti: <16 bytes>

Output:
  SIG1.eyJhbGciOi...<base64>...<base64>
```

### 12.2 Example PoP

```
Request:
  Method: GET
  Path: /api/users
  Host: api.example.com

Canonical String:
  GET\n/api/users\napi.example.com\n1700000000\n<nonce>\n<jti>

Proof Header:
  Signet-Proof: v=1; ts=1700000000; nonce=abc...; kid=xyz; sig=def...
```

## 13. References

- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- NIST SP 800-63B: Digital Identity Guidelines

## Appendix A: Capability Examples

```yaml
# Basic read access
cap_tokens: [0x01]  # read

# Production write
cap_tokens: [0x02, 0x0100]  # write, env:prod

# Admin with constraints
cap_tokens: [0x04, 0x0100, 0x0200]  # admin, env:prod, limit:100
cap_custom:
  rate_limit: 100
  expires: 1700002000
```

## Appendix B: Migration from JWT

|JWT Claim|Signet Field   |Notes                    |
|---------|---------------|-------------------------|
|iss      |iss_id (1)     |Numeric for efficiency   |
|aud      |aud_id (2)     |Numeric + optional string|
|sub      |sub_ppid (3)   |Per-token for privacy    |
|exp      |exp (4)        |Same semantics           |
|scope    |cap_tokens (11)|Semantic capabilities    |
|kid      |kid (10)       |Key identifier           |

-----

*Protocol version 1.0 - Cryptographically enforced proof-of-possession for the modern web*
