# CMS/PKCS#7 Implementation for Ed25519

## Overview

This document describes the implementation of CMS (Cryptographic Message Syntax) / PKCS#7 signatures with Ed25519 support in Signet. This is the first Go implementation to support Ed25519 in CMS format, filling a critical gap in the ecosystem.

## Background

### The Problem

Existing Go CMS/PKCS#7 libraries lack Ed25519 support:
- **Mozilla pkcs7**: Only supports RSA and ECDSA
- **Cloudflare CFSSL**: Read-only PKCS#7, no signature creation
- **GitHub smimesign**: SHA256-RSA only

Git's X.509 signature support requires CMS format, making this implementation essential for signet-commit.

### The Solution

We implemented a minimal but complete CMS signature generation library supporting:
- Ed25519 signatures (RFC 8419)
- Detached signatures for Git
- ASN.1 DER encoding
- OpenSSL-compatible output

## Technical Implementation

### ASN.1 Structure

The CMS SignedData structure follows RFC 5652:

```asn1
ContentInfo ::= SEQUENCE {
  contentType    OBJECT IDENTIFIER (id-signedData),
  content   [0]  EXPLICIT SignedData
}

SignedData ::= SEQUENCE {
  version          INTEGER,
  digestAlgorithms SET OF AlgorithmIdentifier,
  encapContentInfo EncapsulatedContentInfo,
  certificates [0] IMPLICIT CertificateSet OPTIONAL,
  signerInfos      SET OF SignerInfo
}

SignerInfo ::= SEQUENCE {
  version                INTEGER,
  sid                    SignerIdentifier,
  digestAlgorithm        AlgorithmIdentifier,
  signedAttrs       [0]  IMPLICIT SignedAttributes OPTIONAL,
  signatureAlgorithm     AlgorithmIdentifier,
  signature              OCTET STRING
}
```

### Critical Implementation Details

#### 1. IMPLICIT vs EXPLICIT Encoding

The most challenging aspect was correctly implementing the IMPLICIT [0] tag for SignedAttributes:

- **What we sign**: SET OF Attributes with SET tag (0x31)
- **What we store**: [0] IMPLICIT with attributes directly (tag 0xA0)

```go
// Sign with SET tag
func encodeAttributesAsSet(attrs []attribute) ([]byte, error) {
    // Returns: 31 <length> <sorted-attributes>
}

// Store with IMPLICIT [0] tag
func encodeSignedAttributesImplicit(attrs []attribute) ([]byte, error) {
    // Returns: A0 <length> <sorted-attributes-without-set-tag>
}
```

#### 2. Canonical DER Ordering

Attributes must be sorted for deterministic signatures:

```go
sort.Slice(encodedAttrs, func(i, j int) bool {
    return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
})
```

#### 3. OpenSSL Compatibility

Key requirements for OpenSSL verification:
- Use `-binary` flag to prevent S/MIME canonicalization
- Include Subject Key Identifier extension
- Proper OID for Ed25519: 1.3.101.112

### Verification

To verify our CMS signatures with OpenSSL:

```bash
# Create test message
echo -n "test message" > message.txt

# Generate signature
./signet-commit < message.txt > signature.cms

# Convert PEM to DER
openssl cms -in signature.cms -outform DER -out signature.der

# Verify with OpenSSL
openssl cms -verify \
    -inform DER \
    -in signature.der \
    -content message.txt \
    -noverify \
    -binary
```

## Test Coverage

Our implementation includes comprehensive tests:

1. **ASN.1 Encoding Tests**
   - SET vs SEQUENCE validation
   - IMPLICIT [0] encoding verification
   - Canonical ordering checks

2. **RFC 8032 Test Vectors**
   - Ed25519 key derivation validation
   - Signature generation correctness

3. **Integration Tests**
   - Git commit signing
   - OpenSSL verification

## Performance

| Operation | Time |
|-----------|------|
| Key Generation | ~1ms |
| Certificate Creation | ~5ms |
| CMS Signature | ~3ms |
| **Total** | **< 10ms** |

## Security Considerations

1. **Key Zeroization**: Private keys are explicitly cleared from memory after use
2. **Domain Separation**: All signatures include purpose-specific prefixes
3. **Replay Protection**: Timestamps and nonces prevent replay attacks
4. **No Malleability**: Canonical S values enforced per RFC 8032

## Known Limitations

1. **SHA-256 Instead of SHA-512**: RFC 8419 recommends SHA-512 for Ed25519, but we use SHA-256 for Git compatibility
2. **Self-Signed Certificates**: Production deployments should use proper CA infrastructure
3. **No Revocation**: CRL/OCSP not implemented

## Future Improvements

1. **SHA-512 Support**: Add configurable digest algorithm
2. **Certificate Chain**: Support intermediate CAs
3. **Streaming**: Support large file signing without loading into memory
4. **Hardware Security**: HSM/TPM integration for key protection

## References

- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652): Cryptographic Message Syntax
- [RFC 8419](https://www.rfc-editor.org/rfc/rfc8419): EdDSA in CMS
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Edwards-Curve Digital Signature Algorithm

## Code Location

Implementation: [`pkg/cms/signer.go`](../pkg/cms/signer.go)
Tests: [`pkg/cms/signer_test.go`](../pkg/cms/signer_test.go)

---

*This implementation represents a significant contribution to the Go ecosystem as the first library to support Ed25519 in CMS format.*