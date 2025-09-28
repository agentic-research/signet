# ADR-0003: Signet SDK Architecture

**Status:** Draft  
**Type:** Implementation Specification  
**Date:** 2025-09-27  
**Authors:** Signet Contributors

## Context

The Signet protocol requires client-side cryptographic operations that are non-trivial to implement correctly. This ADR defines the SDK architecture, security boundaries, and implementation considerations for client libraries.

## Related Documents

- **[ADR-001: Signet Tokens](./ADR-001-signet-tokens.md)** - Core protocol and token design
- **[ADR-002: Protocol Specification](./ADR-002-protocol-spec.md)** - Wire format specification
- **[Feature Matrix](../FEATURE_MATRIX.md)** - Implementation status across all components

## Decision

Provide official SDKs that abstract cryptographic complexity while maintaining transparency about security properties and limitations.

## SDK Architecture

### Core Components

```
┌─────────────────────────────────────────┐
│            Application Code             │
├─────────────────────────────────────────┤
│            Signet SDK API               │
├─────────────────────────────────────────┤
│  Credential  │  PoP      │  Token      │
│  Manager     │  Generator│  Parser     │
├─────────────────────────────────────────┤
│         Cryptographic Core              │
├─────────────────────────────────────────┤
│      Platform Key Storage               │
└─────────────────────────────────────────┘
```

### Credential Management

The SDK implements automatic credential lifecycle management:

```python
class CredentialManager:
    def __init__(self, config):
        self.issuer_url = config.issuer_url
        self.key_storage = PlatformKeyStorage()
        self.cache = MemoryCache(ttl=300)  # 5 minutes
    
    def get_credential(self, scope):
        # Check cache first
        if cached := self.cache.get(scope):
            if cached.expires_at > time.now() + 30:
                return cached
        
        # Fetch new credential
        return self.fetch_credential(scope)
```

### Key Storage Integration

SDKs MUST integrate with platform-specific secure storage:

|Platform   |Storage Mechanism             |Security Properties           |
|-----------|------------------------------|------------------------------|
|macOS      |Keychain Services             |Hardware-backed when available|
|Linux      |Secret Service API / libsecret|Process isolation             |
|Windows    |Windows Credential Manager    |DPAPI encryption              |
|iOS/Android|Keystore/Keychain             |Hardware security module      |
|Server     |Environment or HSM            |Depends on deployment         |

## Security Considerations

### Current Limitations

#### Ephemeral Key ID Mapping (not true ZK)

**Current Implementation**: The SDK uses ephemeral key IDs to avoid repeated public key transmission, providing privacy-preserving proof of possession:

```python
# Current approach - privacy-preserving ephemeral IDs
def generate_pop_header(self, request):
    # Ephemeral ID that maps to public key
    kid = self.generate_ephemeral_kid()
    self.cache_key_mapping(kid, self.public_key)
    
    # Server still learns the mapping on first use
    return f"kid={kid}; sig={signature}"
```

**Limitation**: The verifier must see the public key at least once to establish the kid→key mapping. This is not true zero-knowledge proof but provides strong privacy properties.

**Mitigation**: This approach prevents correlation across requests after initial registration and is significantly better than bearer tokens. Future versions may implement true zero-knowledge proofs using:

- Ring signatures for anonymity sets
- Bulletproofs for range proofs
- BLS signatures for aggregation

#### Signature Malleability

Ed25519 signatures in the current implementation are malleable for `S` values. While this doesn’t compromise authenticity, it could enable replay variations.

**Mitigation**: Enforce canonical `S` values (0 < S < L/2) per RFC 8032.

#### Clock Synchronization

The protocol assumes reasonably synchronized clocks (±60s). Systems with significant clock drift will experience authentication failures.

**Current Approach**:

- Use server-provided time in responses when available
- Warn on clock skew detection
- Document NTP configuration requirements

### Cryptographic Dependencies

The SDK relies on well-audited cryptographic libraries:

|Language  |Library                |Audit Status             |
|----------|-----------------------|-------------------------|
|Go        |crypto/ed25519 (stdlib)|Go security team         |
|Python    |cryptography.py        |FIPS 140-2 validated core|
|JavaScript|tweetnacl              |Public audit 2017        |
|Rust      |ed25519-dalek          |Security audit 2019      |

**Note**: We do NOT implement cryptographic primitives ourselves.

## Implementation Requirements

### Automatic Retry Logic

```python
class SignetClient:
    @retry(max_attempts=3, backoff=exponential)
    def authenticated_request(self, method, url, body=None):
        credential = self.credential_manager.get_credential()
        proof = self.generate_proof(method, url, body, credential)
        
        response = self.http_client.request(
            method, url, 
            headers={"Signet-Proof": proof},
            body=body
        )
        
        if response.status == 401 and "clock-skew" in response.headers:
            self.adjust_clock_offset(response.headers["server-time"])
            raise RetryableError("Clock adjusted")
            
        return response
```

### Error Transparency

SDKs MUST provide clear error messages for common failures:

```python
class SignetError(Exception):
    pass

class ClockSkewError(SignetError):
    """Local clock differs from server by >60 seconds"""
    
class CapabilityError(SignetError):
    """Token lacks required capabilities"""
    
class RevocationError(SignetError):
    """Token has been revoked"""
```

### Observability

SDKs SHOULD emit structured metrics:

```json
{
  "event": "signet.request",
  "latency_ms": 23,
  "token_age_seconds": 147,
  "capabilities_used": ["read", "env:prod"],
  "cache_hit": true,
  "success": true
}
```

## Developer Experience

### Zero Configuration Operation

```python
# This should "just work" for common cases
from signet import SignetClient

client = SignetClient()  # Discovers issuer from environment
response = client.get("https://api.example.com/users")
```

### Progressive Complexity

```python
# Advanced users can customize behavior
client = SignetClient(
    issuer_url="https://signet.example.com",
    key_storage=HSMKeyStorage(hsm_config),
    cache_backend=RedisCache(redis_config),
    capability_requirements=["read", "env:prod"]
)
```

### Testing Support

```python
# Test mode with deterministic behavior
test_client = SignetClient.test_mode(
    fixed_time=1700000000,
    fixed_nonce=b"0" * 16,
    capabilities=["read", "write", "test"]
)
```

## Migration Support

### Bearer Token Compatibility

During migration, SDKs support dual-mode operation:

```python
client = SignetClient(compatibility_mode=True)

# Attempts Signet first, falls back to bearer
response = client.get(url, fallback_token=jwt_token)

# Logs mode used for gradual migration tracking
# metric: signet.compatibility_mode.bearer_fallback
```

## Performance Considerations

### Caching Strategy

- Credentials cached for MIN(token_ttl - 30s, 5 minutes)
- Key mappings cached for session duration
- Capability evaluations cached per request

### Overhead Targets

|Operation           |Target |Maximum|
|--------------------|-------|-------|
|First request (cold)|< 100ms|200ms  |
|Subsequent requests |< 5ms  |20ms   |
|Credential refresh  |< 50ms |100ms  |
|PoP generation      |< 2ms  |10ms   |

## Known Issues and Future Work

### Current Limitations

1. **Platform Coverage**: Initial SDKs cover Go, Python, JavaScript. Java, Rust, and others planned for Q2.
1. **Hardware Token Support**: Current version uses software keys. Hardware token support (YubiKey, TPM) planned for v1.1.
1. **Batch Operations**: No current support for batch request signing. Under design.
1. **WebAssembly**: Browser WASM support experimental, performance not optimized.

### Research Areas

- True zero-knowledge proofs (zk-SNARKs/ring signatures) for possession without key disclosure
- Post-quantum signature algorithms (Dilithium integration)
- Threshold signatures for distributed systems
- Privacy-preserving capability proofs

## Real HTTP Example

Here's how a Signet-authenticated HTTP request looks in practice:

```http
GET /api/users/me HTTP/1.1
Host: api.example.com
Authorization: Bearer SIG1.eyJpc3MiOiJkaWQ6a2V5Ono2TWt0Li4uIiwiYXVkIjpbImFwaS5leGFtcGxlLmNvbSJdLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDkwMCwiY2FwIjoiN2Y4MzlhLi4uIiwidG9rZW5zIjpbInJlYWQiLCJlbnY6cHJvZCJdfQ.Rn3Kb0V...
Signet-Proof: v=1; ts=1700000000; kid=eph_k1a2b3c4d5; nonce=dGVzdG5vbmNl; proof=bWVzc2FnZXNpZ25hdHVyZQ==
```

The SDK handles all the complexity of generating these headers:

```python
# What the developer writes
response = signet_client.get("/api/users/me")

# What happens under the hood:
# 1. SDK checks credential cache
# 2. Generates ephemeral key if needed
# 3. Creates Signet-Proof header with PoP
# 4. Adds Authorization header with token
# 5. Makes authenticated request
```

## Implementation Maturity

Current implementation status across SDKs and features:

### SDK Status

| SDK | Core Protocol | PoP Generation | Key Storage | Caching | Error Handling | Status |
|-----|--------------|---------------|-------------|---------|---------------|---------|
| Go | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete | **Production** |
| Python | ✅ Complete | 🚧 In Progress | 🚧 In Progress | ⏳ Planned | 🚧 In Progress | **Beta** |
| JavaScript/TS | 🚧 In Progress | ⏳ Planned | ⏳ Planned | ⏳ Planned | ⏳ Planned | **Alpha** |
| Rust | ⏳ Planned | ⏳ Planned | ⏳ Planned | ⏳ Planned | ⏳ Planned | **Planned** |
| WASM | 🔮 Experimental | 🔮 Experimental | N/A | ⏳ Planned | ⏳ Planned | **Experimental** |

### Feature Maturity

| Feature | Status | Notes |
|---------|--------|-------|
| Ed25519 Signatures | ✅ Production | RFC 8032 compliant |
| CBOR Token Parsing | ✅ Production | RFC 8949 compliant |
| Ephemeral Key IDs | ✅ Production | Privacy-preserving, not true ZK |
| Platform Key Storage | ✅ Production | macOS, Linux, Windows |
| Automatic Renewal | ✅ Production | Smart refresh logic |
| Batch Operations | 🚧 In Progress | Design phase |
| True ZK Proofs | 🔮 Research | Exploring ring signatures |
| Post-Quantum | 🔮 Research | Dilithium under consideration |

**Legend:**
- ✅ Complete and tested
- 🚧 Under active development
- ⏳ Planned for next quarter
- 🔮 Experimental/Research
- N/A Not applicable

## Testing

```bash
# Run protocol conformance tests
signet-test-suite --implementation ./my-sdk

# Expected output:
✓ Token parsing (RFC 8949 CBOR)
✓ Signature verification (Ed25519)
✓ PoP generation canonical string
✓ Capability computation (128-bit)
✓ Clock skew handling (±60s)
✓ Retry logic (exponential backoff)
✓ Error messages (clear, actionable)
```

## Security Disclosure

Security issues should be reported via:

- Email: security@signet-auth.org
- PGP Key: [published on keyserver]

We request 90 days to address issues before public disclosure.

## License

SDKs are released under Apache 2.0 to encourage adoption while maintaining compatibility.

## Acknowledgments

The SDK architecture benefits from lessons learned from:

- AWS Signature v4 (request signing)
- Google Application Default Credentials (credential discovery)
- Let’s Encrypt’s Certbot (automated certificate management)

-----

*Building secure authentication that developers don’t have to think about*
