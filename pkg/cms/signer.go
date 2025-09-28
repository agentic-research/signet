package cms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
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

// SignData creates a detached CMS/PKCS#7 signature for Git
func SignData(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey) ([]byte, error) {
	// 1. Create signed attributes
	signedAttrs, err := createSignedAttributes(data)
	if err != nil {
		return nil, err
	}

	// 2. Sign the attributes
	signature, err := signAttributes(signedAttrs, privateKey)
	if err != nil {
		return nil, err
	}

	// 3. Marshal SignedAttrs as SET for inclusion in SignerInfo
	// Key fix: Go's default slice marshaling uses SEQUENCE, we need SET
	type attributeSet struct {
		Attributes []attribute `asn1:"set"`
	}
	tempSet := attributeSet{Attributes: signedAttrs}
	signedAttrsBytes, err := asn1.Marshal(tempSet)
	if err != nil {
		return nil, err
	}
	
	// Extract just the SET contents (skip the wrapping SEQUENCE)
	// The marshal creates SEQUENCE { SET { attrs... } }, we want just SET { attrs... }
	var rawSet asn1.RawValue
	if _, err := asn1.Unmarshal(signedAttrsBytes, &rawSet); err != nil {
		return nil, err
	}

	// 4. Build the SignedData structure
	sd := signedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: oidData,
			// Content is omitted for detached signature
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
				SignedAttrsRaw: asn1.RawValue{
					Class:      2, // context-specific
					Tag:        0,
					IsCompound: true,
					Bytes:      rawSet.Bytes, // This is now a proper SET
				},
				SignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oidEd25519,
				},
				Signature: signature,
			},
		},
	}

	// 5. Marshal the SignedData
	signedDataBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	// 6. Build the ContentInfo wrapper
	cms := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      2, // context-specific
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	// 7. Encode to DER
	return asn1.Marshal(cms)
}

// ASN.1 structures for CMS/PKCS#7
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	Sid                issuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrsRaw     asn1.RawValue `asn1:"optional"` // Using RawValue for manual encoding
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// createSignedAttributes creates the signed attributes for CMS
func createSignedAttributes(data []byte) ([]attribute, error) {
	// Calculate message digest
	hash := crypto.SHA256.New()
	hash.Write(data)
	messageDigest := hash.Sum(nil)

	// Encode attributes
	contentTypeValue, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}

	messageDigestValue, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, err
	}

	signingTimeValue, err := asn1.Marshal(time.Now().UTC())
	if err != nil {
		return nil, err
	}

	return []attribute{
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{FullBytes: contentTypeValue},
		},
		{
			Type:  oidAttributeSigningTime,
			Value: asn1.RawValue{FullBytes: signingTimeValue},
		},
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{FullBytes: messageDigestValue},
		},
	}, nil
}

// signAttributes signs the DER-encoded attributes
func signAttributes(attrs []attribute, privateKey ed25519.PrivateKey) ([]byte, error) {
	// Encode attributes for signing
	encoded, err := asn1.Marshal(struct {
		Attributes []attribute `asn1:"set"`
	}{attrs})
	if err != nil {
		return nil, err
	}

	// Sign with Ed25519
	signature := ed25519.Sign(privateKey, encoded)
	if signature == nil {
		return nil, errors.New("failed to create signature")
	}

	return signature, nil
}