# HTTP Proof-of-Possession at Edge Proxies

```
Network Working Group                                         J. Gardner
Intended status: Standards Track                      27 September 2025
Expires: March 2026
```

## Abstract

This document defines a method for edge proxies to verify proof-of-possession (PoP) for incoming HTTP requests and translate verified identities to internal authentication mechanisms. This pattern enables strong authentication for external clients while maintaining simplified authentication within trusted network boundaries.

## Status of This Memo

This has not been formally submitted and exists solely in this repo.
Internet-Drafts are working documents of the Internet Engineering Task Force (IETF). Note that other groups may also distribute working documents as Internet-Drafts. The list of current Internet-Drafts is at https://datatracker.ietf.org/drafts/current/.

## Copyright Notice

Copyright (c) 2025 IETF Trust and the persons identified as the document authors. All rights reserved.

## 1. Introduction

Bearer tokens transmitted in HTTP headers are vulnerable to theft and replay attacks. Even with transport security (TLS), a compromised token can be used by an attacker from any location until expiration. While proof-of-possession mechanisms exist for various protocols, there is no standard for translating PoP-verified requests at network edges to simplified internal authentication.

This document specifies:
- A method for edge proxies to verify proof-of-possession
- Translation to internal authentication mechanisms (mTLS, trusted headers)
- Capability propagation from edge to internal services

### 1.1 Motivation

Modern microservice architectures often have hundreds of internal service-to-service calls for each external API request. Requiring proof-of-possession verification at each internal hop introduces unnecessary latency and complexity. This specification enables PoP verification once at the edge, with trusted communication internally.

### 1.2 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [RFC2119].

- **Edge Proxy**: A reverse proxy at the network boundary that handles incoming external requests
- **Proof-of-Possession (PoP)**: Cryptographic proof that the presenter possesses a specific private key
- **Internal Service**: A service within the trusted network boundary
- **Capability**: A semantic permission or access right

## 2. Architecture Overview

```
   External Client          Edge Proxy              Internal Services
        |                       |                          |
        |--PoP Token + Proof--->|                          |
        |                       |--Verify PoP              |
        |                       |--Extract Capabilities    |
        |                       |--Translate to mTLS------>|
        |                       |                          |
        |<---Response-----------|<-------Response----------|
```

## 3. Proof-of-Possession at Edge

### 3.1 Token Format

The edge proxy MUST accept tokens that include a confirmation claim binding the token to a cryptographic key, as specified in RFC 8705 [RFC8705]:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "cnf": {
    "jkt": "SHA256:abc..."  // Key thumbprint
  },
  "capabilities": ["read", "env:prod"]
}
```

### 3.2 Proof Header

Clients MUST include a proof header demonstrating possession of the private key:

```
PoP-Proof: v=1; ts=1700000000; nonce=abc123; sig=<signature>
```

The signature MUST be computed over the canonical string:
```
<method>\n<path>\n<host>\n<timestamp>\n<nonce>
```

### 3.3 Edge Verification

The edge proxy MUST:
1. Validate the token signature and expiration
2. Verify the PoP-Proof signature matches the key bound in the token
3. Check nonce uniqueness within the timestamp window
4. Extract capabilities from the token

## 4. Translation to Internal Authentication

### 4.1 mTLS Translation

When internal services use mutual TLS, the edge proxy:

```
1. Verifies external PoP
2. Selects appropriate client certificate based on verified identity
3. Establishes mTLS connection to internal service
4. Forwards request with mTLS authentication
```

### 4.2 Trusted Header Injection

For internal services using header-based authentication:

```
X-Internal-User: user@example.com
X-Internal-Capabilities: read,env:prod
X-Edge-Verified: true
X-Edge-Timestamp: 1700000000
```

Internal services MUST only trust these headers from authenticated edge proxies.

### 4.3 Capability Propagation

Semantic capabilities extracted from the PoP token SHOULD be propagated as:
- mTLS certificate attributes (Subject Alternative Names)
- HTTP headers for capability-aware services
- Service mesh metadata

## 5. Security Considerations

### 5.1 Trust Boundary

The security of this pattern depends on the network boundary between the edge proxy and internal services being properly secured. Internal services MUST NOT accept external connections bypassing the edge proxy.

### 5.2 Edge Proxy Compromise

If an edge proxy is compromised, it can forge internal authentication. Edge proxies MUST be hardened and monitored as critical security infrastructure.

### 5.3 Replay Prevention

Edge proxies MUST maintain a cache of seen nonces within the timestamp window (RECOMMENDED: 60 seconds) to prevent replay attacks.

### 5.4 Clock Synchronization

Clients and edge proxies SHOULD synchronize clocks via NTP. Proxies SHOULD allow ±60 seconds clock skew.

## 6. Implementation Considerations

### 6.1 Performance

Edge proxies SHOULD:
- Cache token validation results for the token lifetime
- Use connection pooling for internal mTLS connections
- Implement rate limiting per client identity

### 6.2 Observability

Edge proxies SHOULD emit metrics for:
- PoP verification failures (by reason)
- Translation latency
- Capability usage patterns

### 6.3 Migration

Services MAY operate in dual mode during migration:
```
if has_pop_proof(request):
    verify_pop(request)
else:
    verify_bearer_token(request)  # Legacy path
```

## 7. Examples

### 7.1 External Request with PoP

```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
PoP-Proof: v=1; ts=1700000000; nonce=abc123; sig=def456...
```

### 7.2 Internal Request after Translation

```http
GET /api/users HTTP/1.1
Host: internal-api.local
X-Internal-User: user@example.com
X-Internal-Capabilities: read,env:prod
X-Edge-Verified: true
[mTLS client certificate presented at TLS layer]
```

## 8. IANA Considerations

This document requests registration of:
- HTTP Header: `PoP-Proof`
- HTTP Header: `X-Internal-User`
- HTTP Header: `X-Internal-Capabilities`
- HTTP Header: `X-Edge-Verified`

## 9. References

### 9.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC8705] Campbell, B., et al., "OAuth 2.0 Mutual-TLS Client Authentication", RFC 8705, February 2020.
- [RFC9449] Fett, D., et al., "OAuth 2.0 Demonstrating Proof of Possession", RFC 9449, September 2023.

### 9.2 Informative References

- [RFC8246] McManus, P., "HTTP Immutable Responses", RFC 8246, September 2017.
- [SIGSTORE] "Sigstore: A Solution to Software Supply Chain Security", https://www.sigstore.dev/

## Appendix A. Deployment Patterns

### A.1 Kubernetes Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "https://pop-verifier/verify"
    nginx.ingress.kubernetes.io/auth-snippet: |
      proxy_set_header X-Internal-User $auth_user;
      proxy_set_header X-Internal-Capabilities $auth_capabilities;
```

### A.2 Service Mesh

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: edge-translation
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/edge-proxy/sa/verifier"]
    when:
    - key: request.headers[x-edge-verified]
      values: ["true"]
```

## Acknowledgments

This pattern is inspired by existing internal implementations at major cloud providers and the Sigstore project's approach to software signing.

## Author's Address

James Gardner
github: @jamestexas
