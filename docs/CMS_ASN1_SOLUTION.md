# CMS/PKCS#7 ASN.1 Encoding Solution for Ed25519 Signatures

## Executive Summary

The critical issue is that Go's `encoding/asn1` package marshals slices as SEQUENCE (tag 0x30) by default, but RFC 5652 requires SignedAttributes to be encoded as `[0] IMPLICIT SET OF Attribute`. The mismatch between SEQUENCE (0x30) and SET (0x31) at the byte level causes OpenSSL/gpgsm to reject the signature with ASN.1 encoding errors.

## The Fundamental Problem

### Mathematical/Theoretical Analysis

From a type-theoretic perspective, SET and SEQUENCE are fundamentally different algebraic structures:
- **SEQUENCE**: Ordered collection with position-dependent semantics
- **SET**: Unordered collection with position-independent semantics

In ASN.1 DER encoding:
- SEQUENCE uses tag 0x30 (decimal 48)
- SET uses tag 0x31 (decimal 49)

The RFC 5652 specification requires:
```asn1
SignedAttributes ::= [0] IMPLICIT SET SIZE (1..MAX) OF Attribute
```

The `IMPLICIT` keyword means the SET tag is replaced by the context-specific tag [0], not wrapped by it.

### Current Implementation Bug

Your current code attempts to create the correct structure but fails at the byte level:

```go
// Current approach - INCORRECT
type attributeSet struct {
    Attributes []attribute `asn1:"set"`
}
tempSet := attributeSet{Attributes: signedAttrs}
signedAttrsBytes, err := asn1.Marshal(tempSet)
```

This creates:
```
SEQUENCE {           // 0x30 - outer wrapper from struct
    SET {            // 0x31 - from asn1:"set" tag
        Attribute,
        Attribute,
        ...
    }
}
```

Then extracting and wrapping in [0] produces:
```
[0] {                // 0xA0 - context-specific
    SET {            // 0x31 - the SET we wanted
        Attribute,
        ...
    }
}
```

But this is `[0] EXPLICIT SET`, not `[0] IMPLICIT SET`.

## The Correct Solution

### Implementation Strategy

The solution requires direct byte-level manipulation to achieve IMPLICIT tagging:

```go
// Solution: Manual SET construction with IMPLICIT tagging
func encodeSignedAttributes(attrs []attribute) (asn1.RawValue, error) {
    // Step 1: Encode each attribute individually
    var encodedAttrs [][]byte
    for _, attr := range attrs {
        // Encode the attribute as a SEQUENCE
        attrBytes, err := asn1.Marshal(attr)
        if err != nil {
            return asn1.RawValue{}, err
        }
        encodedAttrs = append(encodedAttrs, attrBytes)
    }
    
    // Step 2: Sort attributes by DER encoding (canonical form)
    // This is required for SET OF in DER encoding
    sort.Slice(encodedAttrs, func(i, j int) bool {
        return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
    })
    
    // Step 3: Concatenate all encoded attributes
    var setContents []byte
    for _, attrBytes := range encodedAttrs {
        setContents = append(setContents, attrBytes...)
    }
    
    // Step 4: Create [0] IMPLICIT tag (replaces SET tag)
    // For IMPLICIT, we use the context tag directly without the SET tag
    return asn1.RawValue{
        Class:      2,    // Context-specific
        Tag:        0,    // [0]
        IsCompound: true, // Contains other elements
        Bytes:      setContents,
    }, nil
}
```

### Alternative Solution Using Two-Pass Encoding

```go
func encodeSignedAttributesAlternative(attrs []attribute) (asn1.RawValue, error) {
    // First, marshal as a SET
    setBytes, err := asn1.Marshal(struct {
        Attrs []attribute `asn1:"set"`
    }{Attrs: attrs})
    if err != nil {
        return asn1.RawValue{}, err
    }
    
    // Parse to extract the SET
    var parsed asn1.RawValue
    rest, err := asn1.Unmarshal(setBytes, &parsed)
    if err != nil || len(rest) > 0 {
        return asn1.RawValue{}, fmt.Errorf("failed to parse SET")
    }
    
    // Find the SET within (skip SEQUENCE wrapper if present)
    if parsed.Tag == 16 { // SEQUENCE tag
        // Extract the SET from inside
        rest, err = asn1.Unmarshal(parsed.Bytes, &parsed)
        if err != nil || len(rest) > 0 {
            return asn1.RawValue{}, fmt.Errorf("failed to extract SET")
        }
    }
    
    // Verify we have a SET
    if parsed.Tag != 17 { // SET tag
        return asn1.RawValue{}, fmt.Errorf("expected SET, got tag %d", parsed.Tag)
    }
    
    // Return as [0] IMPLICIT (replacing the SET tag)
    return asn1.RawValue{
        Class:      2,
        Tag:        0,
        IsCompound: true,
        Bytes:      parsed.Bytes, // Contents of the SET without the SET tag
    }, nil
}
```

## Complete Working Implementation

Here's the corrected signer.go section:

```go
// SignData creates a detached CMS/PKCS#7 signature for Git
func SignData(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey) ([]byte, error) {
    // 1. Create signed attributes
    signedAttrs, err := createSignedAttributes(data)
    if err != nil {
        return nil, err
    }

    // 2. Encode SignedAttrs for signature calculation
    // For signature, we need SET OF without the [0] tag
    signedAttrsForSigning, err := encodeAttributesAsSet(signedAttrs)
    if err != nil {
        return nil, err
    }
    
    // 3. Sign the SET OF attributes
    signature := ed25519.Sign(privateKey, signedAttrsForSigning)

    // 4. Encode SignedAttrs for inclusion in SignerInfo
    signedAttrsRaw, err := encodeSignedAttributesImplicit(signedAttrs)
    if err != nil {
        return nil, err
    }

    // 5. Build the SignedData structure
    sd := signedData{
        Version: 1,
        DigestAlgorithms: []pkix.AlgorithmIdentifier{
            {Algorithm: oidSHA256},
        },
        EncapContentInfo: encapsulatedContentInfo{
            ContentType: oidData,
        },
        Certificates: []asn1.RawValue{
            {FullBytes: cert.Raw},
        },
        SignerInfos: []signerInfo{
            {
                Version: 1,
                Sid: issuerAndSerialNumber{
                    Issuer:       cert.Issuer.ToRDNSequence(),
                    SerialNumber: cert.SerialNumber,
                },
                DigestAlgorithm: pkix.AlgorithmIdentifier{
                    Algorithm: oidSHA256,
                },
                SignedAttrsRaw: signedAttrsRaw,
                SignatureAlgorithm: pkix.AlgorithmIdentifier{
                    Algorithm: oidEd25519,
                },
                Signature: signature,
            },
        },
    }

    // Continue with rest of implementation...
}

// encodeAttributesAsSet encodes attributes as SET OF for signing
func encodeAttributesAsSet(attrs []attribute) ([]byte, error) {
    // Create temporary struct to force SET encoding
    type setWrapper struct {
        Attrs []attribute `asn1:"set"`
    }
    
    wrapper := setWrapper{Attrs: attrs}
    encoded, err := asn1.Marshal(wrapper)
    if err != nil {
        return nil, err
    }
    
    // Extract just the SET (skip wrapper SEQUENCE)
    var parsed asn1.RawValue
    _, err = asn1.Unmarshal(encoded, &parsed)
    if err != nil {
        return nil, err
    }
    
    // If we got a SEQUENCE, extract the SET from inside
    if parsed.Tag == 16 { // SEQUENCE
        var inner asn1.RawValue
        _, err = asn1.Unmarshal(parsed.Bytes, &inner)
        if err != nil {
            return nil, err
        }
        if inner.Tag != 17 { // SET
            return nil, fmt.Errorf("expected SET, got tag %d", inner.Tag)
        }
        // Return complete SET with tag
        return encoded[len(encoded)-len(inner.FullBytes):], nil
    }
    
    return parsed.FullBytes, nil
}

// encodeSignedAttributesImplicit creates [0] IMPLICIT SET OF
func encodeSignedAttributesImplicit(attrs []attribute) (asn1.RawValue, error) {
    // Get the SET encoding
    setBytes, err := encodeAttributesAsSet(attrs)
    if err != nil {
        return asn1.RawValue{}, err
    }
    
    // Parse to get contents without SET tag
    var setRaw asn1.RawValue
    _, err = asn1.Unmarshal(setBytes, &setRaw)
    if err != nil {
        return asn1.RawValue{}, err
    }
    
    // Return as [0] IMPLICIT (contents only, no SET tag)
    return asn1.RawValue{
        Class:      2,    // Context-specific
        Tag:        0,    // [0]
        IsCompound: true,
        Bytes:      setRaw.Bytes, // Contents without SET tag
    }, nil
}
```

## Test Vectors

### Correct ASN.1 Structure

```
SignerInfo SEQUENCE {
    version INTEGER (1)
    sid IssuerAndSerialNumber
    digestAlgorithm AlgorithmIdentifier
    signedAttrs [0] IMPLICIT {         # Tag: 0xA0
        # Direct attribute contents, no SET tag
        SEQUENCE { contentType ... }    # First attribute
        SEQUENCE { signingTime ... }    # Second attribute
        SEQUENCE { messageDigest ... }  # Third attribute
    }
    signatureAlgorithm AlgorithmIdentifier
    signature OCTET STRING
}
```

### Byte-Level Example

Incorrect (current):
```
A0 1E 31 1C ...  # [0] EXPLICIT SET
```

Correct (needed):
```
A0 1C ...  # [0] IMPLICIT with SET contents directly
```

The difference is subtle but critical - IMPLICIT means the context tag replaces the SET tag rather than wrapping it.

## Verification Method

To verify the fix works:

1. **OpenSSL Test**:
```bash
openssl cms -verify -in signature.pem -inform PEM -noverify -out /dev/null
```

2. **ASN.1 Dump**:
```bash
openssl asn1parse -in signature.pem -inform PEM -i
```

Look for:
```
    cont [ 0 ]        # This should directly contain attributes
      SEQUENCE        # First attribute (not wrapped in SET)
      SEQUENCE        # Second attribute
      SEQUENCE        # Third attribute
```

## Summary

The fix requires understanding the subtle difference between EXPLICIT and IMPLICIT tagging in ASN.1:
- **EXPLICIT**: Adds a wrapper tag around the original structure
- **IMPLICIT**: Replaces the original tag with the new tag

For `[0] IMPLICIT SET OF`, the context-specific tag [0] replaces the SET tag entirely, meaning the encoded form should have tag 0xA0 directly containing the concatenated attribute encodings, not 0xA0 containing 0x31 (SET).

This is a fundamental ASN.1 encoding issue that requires careful byte-level manipulation to resolve correctly. The solution provided above handles this properly while maintaining compatibility with RFC 5652 requirements.