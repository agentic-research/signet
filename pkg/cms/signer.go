// Package cms implements CMS/PKCS#7 signature generation with Ed25519 support.
//
// This package fills a gap in the Go ecosystem as existing CMS libraries
// (mozilla/pkcs7, cloudflare/cfssl) do not support Ed25519 signatures.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sort"
	"time"

	signetErrors "github.com/jamestexas/signet/pkg/errors"
)

// OID definitions for CMS/PKCS#7
var (
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidEd25519                = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// SignData creates a detached CMS/PKCS#7 signature using Ed25519.
//
// This function implements RFC 5652 (CMS) with RFC 8410 (Ed25519 in CMS).
// The signature is detached (does not include the original data).
//
// Parameters:
//   - data: The data to be signed
//   - cert: The X.509 certificate containing the public key
//   - privateKey: The Ed25519 private key for signing
//
// Returns:
//   - DER-encoded CMS/PKCS#7 signature
func SignData(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey) ([]byte, error) {
	// 1. Calculate message digest
	hash := crypto.SHA256.New()
	hash.Write(data)
	messageDigest := hash.Sum(nil)

	// 2. Create signed attributes
	signedAttrs := createSignedAttributes(messageDigest)

	// 3. Encode attributes as SET for signing (with SET tag)
	setForSigning, err := encodeAttributesAsSet(signedAttrs)
	if err != nil {
		return nil, signetErrors.NewSignatureError("cms", "failed to encode attributes as SET", err)
	}

	// 4. Sign the SET OF attributes
	signature := ed25519.Sign(privateKey, setForSigning)
	if signature == nil {
		return nil, signetErrors.NewSignatureError("cms", "failed to create signature", nil)
	}

	// 5. Encode attributes as [0] IMPLICIT for storage in SignerInfo
	implicitAttrs, err := encodeSignedAttributesImplicit(signedAttrs)
	if err != nil {
		return nil, signetErrors.NewSignatureError("cms", "failed to encode attributes as IMPLICIT", err)
	}

	// 6. Build SignerInfo with the IMPLICIT encoded attributes
	signerInfo, err := buildSignerInfo(cert, implicitAttrs, signature)
	if err != nil {
		return nil, err
	}

	// 7. Build complete CMS structure
	cmsBytes, err := buildCMS(cert, signerInfo)
	if err != nil {
		return nil, err
	}

	return cmsBytes, nil
}

// attribute represents a CMS attribute
type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// createSignedAttributes creates the signed attributes for CMS
func createSignedAttributes(messageDigest []byte) []attribute {
	// Encode attribute values - each must be wrapped in a SET
	contentTypeValue, _ := asn1.Marshal(oidData)
	messageDigestValue, _ := asn1.Marshal(messageDigest)
	signingTimeValue, _ := asn1.Marshal(time.Now().UTC())


	return []attribute{
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      contentTypeValue,
			},
		},
		{
			Type:  oidAttributeSigningTime,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      signingTimeValue,
			},
		},
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      messageDigestValue,
			},
		},
	}
}

// wrapInSet wraps data in an ASN.1 SET tag
func wrapInSet(data []byte) []byte {
	result := []byte{0x31} // SET tag
	if len(data) < 128 {
		result = append(result, byte(len(data)))
	} else if len(data) < 256 {
		result = append(result, 0x81, byte(len(data)))
	} else {
		result = append(result, 0x82, byte(len(data)>>8), byte(len(data)))
	}
	return append(result, data...)
}

// encodeAttributesAsSet creates a proper SET OF Attribute for signing
// Returns the complete SET with tag 0x31
func encodeAttributesAsSet(attrs []attribute) ([]byte, error) {
	// Step 1: Marshal each attribute individually
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		attrBytes, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, attrBytes)
	}

	// Step 2: Sort for canonical SET OF ordering (DER requirement)
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Step 3: Concatenate sorted attributes
	var buf bytes.Buffer
	for _, attrBytes := range encodedAttrs {
		buf.Write(attrBytes)
	}
	content := buf.Bytes()

	// Step 4: Create SET with tag 0x31
	result := []byte{0x31} // SET tag

	// Add length
	if len(content) < 128 {
		result = append(result, byte(len(content)))
	} else if len(content) < 256 {
		result = append(result, 0x81, byte(len(content)))
	} else {
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}

	// Add content
	result = append(result, content...)
	return result, nil
}

// encodeSignedAttributesImplicit creates [0] IMPLICIT SET OF for storage in SignerInfo
// Returns tag 0xA0 with SET contents (no SET tag)
func encodeSignedAttributesImplicit(attrs []attribute) ([]byte, error) {
	// Step 1: Marshal each attribute individually
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		attrBytes, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, attrBytes)
	}

	// Step 2: Sort for canonical SET OF ordering
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Step 3: Concatenate sorted attributes (SET contents without SET tag)
	var buf bytes.Buffer
	for _, attrBytes := range encodedAttrs {
		buf.Write(attrBytes)
	}
	content := buf.Bytes()

	// Step 4: Create [0] IMPLICIT (replaces SET tag with context tag)
	result := []byte{0xA0} // Context-specific, constructed, tag 0

	// Add length
	if len(content) < 128 {
		result = append(result, byte(len(content)))
	} else if len(content) < 256 {
		result = append(result, 0x81, byte(len(content)))
	} else {
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}

	// Add content (no SET tag, just the concatenated attributes)
	result = append(result, content...)
	return result, nil
}

// buildSignerInfo manually constructs SignerInfo with proper IMPLICIT [0] for signedAttrs
func buildSignerInfo(cert *x509.Certificate, signedAttrsBytes []byte, signature []byte) ([]byte, error) {
	var buf bytes.Buffer

	// Version (INTEGER 1)
	versionBytes, _ := asn1.Marshal(1)
	buf.Write(versionBytes)

	// IssuerAndSerialNumber
	issuerAndSerial := struct {
		Issuer       pkix.RDNSequence
		SerialNumber *big.Int
	}{
		Issuer:       cert.Issuer.ToRDNSequence(),
		SerialNumber: cert.SerialNumber,
	}
	issuerBytes, err := asn1.Marshal(issuerAndSerial)
	if err != nil {
		return nil, err
	}
	buf.Write(issuerBytes)

	// DigestAlgorithm
	digestAlg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	digestAlgBytes, _ := asn1.Marshal(digestAlg)
	buf.Write(digestAlgBytes)

	// SignedAttrs as IMPLICIT [0] SET OF Attribute - use the pre-encoded bytes
	buf.Write(signedAttrsBytes)

	// SignatureAlgorithm
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	sigAlgBytes, _ := asn1.Marshal(sigAlg)
	buf.Write(sigAlgBytes)

	// Signature (OCTET STRING)
	sigBytes, _ := asn1.Marshal(signature)
	buf.Write(sigBytes)

	// Wrap in SEQUENCE
	content := buf.Bytes()
	seqHeader := makeSequenceHeader(len(content))

	result := append(seqHeader, content...)
	return result, nil
}

// buildCMS builds the complete CMS ContentInfo structure
func buildCMS(cert *x509.Certificate, signerInfo []byte) ([]byte, error) {
	// Build SignedData
	var sdBuf bytes.Buffer
	
	// Version (INTEGER 1)
	versionBytes, _ := asn1.Marshal(1)
	sdBuf.Write(versionBytes)
	
	// DigestAlgorithms (SET OF AlgorithmIdentifier)
	digestAlgs := []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}}
	digestAlgsBytes, _ := asn1.Marshal(digestAlgs)
	// Change SEQUENCE to SET tag
	if len(digestAlgsBytes) > 0 && digestAlgsBytes[0] == 0x30 {
		digestAlgsBytes[0] = 0x31
	}
	sdBuf.Write(digestAlgsBytes)
	
	// EncapContentInfo
	encapContent := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}{
		ContentType: oidData,
		// Content omitted for detached signature
	}
	encapBytes, _ := asn1.Marshal(encapContent)
	sdBuf.Write(encapBytes)
	
	// Certificates [0] IMPLICIT
	certHeader := []byte{0xA0} // context-specific, constructed, tag 0
	if len(cert.Raw) < 128 {
		certHeader = append(certHeader, byte(len(cert.Raw)))
	} else {
		certLen := len(cert.Raw)
		if certLen < 256 {
			certHeader = append(certHeader, 0x81, byte(certLen))
		} else if certLen < 65536 {
			certHeader = append(certHeader, 0x82, byte(certLen>>8), byte(certLen))
		} else {
			return nil, signetErrors.NewValidationError("certificate size", "", "certificate too large", nil)
		}
	}
	sdBuf.Write(certHeader)
	sdBuf.Write(cert.Raw)
	
	// SignerInfos (SET OF SignerInfo)
	siSetHeader := makeSetHeader(len(signerInfo))
	sdBuf.Write(siSetHeader)
	sdBuf.Write(signerInfo)
	
	// Wrap SignedData in SEQUENCE
	sdContent := sdBuf.Bytes()
	sdSeqHeader := makeSequenceHeader(len(sdContent))
	signedData := append(sdSeqHeader, sdContent...)
	
	// Build ContentInfo
	var ciBuf bytes.Buffer
	
	// ContentType (OBJECT IDENTIFIER)
	contentTypeBytes, _ := asn1.Marshal(oidSignedData)
	ciBuf.Write(contentTypeBytes)
	
	// Content [0] EXPLICIT
	contentHeader := []byte{0xA0} // context-specific, constructed, tag 0
	if len(signedData) < 128 {
		contentHeader = append(contentHeader, byte(len(signedData)))
	} else {
		contentLen := len(signedData)
		if contentLen < 256 {
			contentHeader = append(contentHeader, 0x81, byte(contentLen))
		} else if contentLen < 65536 {
			contentHeader = append(contentHeader, 0x82, byte(contentLen>>8), byte(contentLen))
		} else {
			return nil, signetErrors.NewValidationError("content size", "", "content too large", nil)
		}
	}
	ciBuf.Write(contentHeader)
	ciBuf.Write(signedData)
	
	// Wrap ContentInfo in SEQUENCE
	ciContent := ciBuf.Bytes()
	ciSeqHeader := makeSequenceHeader(len(ciContent))
	
	return append(ciSeqHeader, ciContent...), nil
}

// makeSequenceHeader creates a SEQUENCE header with the given length
func makeSequenceHeader(length int) []byte {
	header := []byte{0x30} // SEQUENCE tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		// For very large structures
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}

// makeSetHeader creates a SET header with the given length
func makeSetHeader(length int) []byte {
	header := []byte{0x31} // SET tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		// For very large structures
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}