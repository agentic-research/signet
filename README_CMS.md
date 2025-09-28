# CMS/PKCS#7 with Ed25519 Support

## Overview

This package provides CMS/PKCS#7 signature generation with Ed25519 support for Go. It implements the necessary ASN.1 encoding for creating detached signatures compatible with Git's X.509 signing format.

## Background

Existing Go CMS/PKCS#7 libraries (mozilla/pkcs7, cloudflare/cfssl, github/smimesign) do not support Ed25519 signatures, as they primarily focus on RSA and ECDSA algorithms. This implementation fills that gap.

## Implementation Status

Currently, the implementation:
- ✅ Generates valid CMS/PKCS#7 signatures with Ed25519
- ✅ Works with Git commit signing
- ⚠️ Has known ASN.1 encoding issues with SignedAttributes (see Technical Notes)

## Technical Notes

### ASN.1 Encoding Challenge

The implementation currently faces an encoding issue with SignedAttributes. RFC 5652 requires:
```
SignedAttributes ::= [0] IMPLICIT SET OF Attribute
```

The challenge is that Go's `encoding/asn1` package defaults to SEQUENCE encoding for slices, while the specification requires SET encoding with IMPLICIT tagging. This causes verification failures with OpenSSL and gpgsm.

See `docs/CMS_ASN1_SOLUTION.md` for detailed analysis and proposed solutions.

### Ed25519 Support

Ed25519 signatures use OID `1.3.101.112` as specified in RFC 8410. The implementation follows RFC 8032 for signature generation.

## Usage

```go
import "github.com/jamestexas/signet/pkg/cms"

// Create a detached CMS signature
signature, err := cms.SignData(data, cert, privateKey)
```

## Testing

Integration testing with Git:
```bash
make integration-test
```

Verify ASN.1 structure:
```bash
openssl asn1parse -inform DER -in signature.der
```

## Contributing

This is an active area of development. Key areas needing work:
- Correct IMPLICIT SET encoding for SignedAttributes
- OpenSSL/gpgsm verification compatibility
- Comprehensive test suite

## References

- RFC 5652: Cryptographic Message Syntax (CMS)
- RFC 8410: Algorithm Identifiers for Ed25519
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)