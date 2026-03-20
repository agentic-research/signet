package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/url"
	"time"
)

// OIDSignetCapabilities is the OID for the signet capability attestation extension.
// Arc: 1.3.6.1.4.1.99999.1.3 (next after .1=subject, .2=issuance time).
var OIDSignetCapabilities = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}

// IssueBridgeCertificate creates an intermediate CA certificate that embeds
// capability URIs as an X.509 extension. The bridge cert is IsCA:true with
// MaxPathLen:0, allowing it to issue ephemeral end-entity certs but not
// further intermediates.
//
// The capabilities are encoded as ASN.1 SEQUENCE OF UTF8String under
// OID 1.3.6.1.4.1.99999.1.3.
func (ca *LocalCA) IssueBridgeCertificate(
	ephemeralPubKey crypto.PublicKey,
	capabilities []string,
	validity time.Duration,
) (*x509.Certificate, []byte, error) {
	if ephemeralPubKey == nil {
		return nil, nil, errors.New("ephemeral public key cannot be nil")
	}
	if validity <= 0 {
		return nil, nil, errors.New("validity duration must be positive")
	}

	// Encode capabilities as ASN.1 SEQUENCE OF UTF8String
	capExt, err := MarshalCapabilities(capabilities)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	// Parse DID as URI for SAN (consistent with all other LocalCA templates)
	didURI, _ := url.Parse(ca.issuerDID)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               EncodeDIDAsSubject(ca.issuerDID),
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		URIs:                  []*url.URL{didURI},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          generateSubjectKeyID(ephemeralPubKey),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSignetCapabilities,
				Value: capExt,
			},
		},
	}

	issuerTemplate := ca.CreateCACertificateTemplate()
	if issuerTemplate == nil {
		return nil, nil, errors.New("failed to create issuer template")
	}
	issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
	template.AuthorityKeyId = issuerTemplate.SubjectKeyId

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuerTemplate,
		ephemeralPubKey,
		ca.masterKey,
	)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, certDER, nil
}

// MarshalCapabilities encodes capability URIs as ASN.1 SEQUENCE OF UTF8String.
//
// Interop contract (must match TypeScript @peculiar/x509 implementation):
//
//	DER encoding: SEQUENCE { UTF8String, UTF8String, ... }
//	ASN.1 tags:   SEQUENCE = 0x30, UTF8String = 0x0C
//	Empty list:   SEQUENCE {} = 0x30 0x00
//
// Example: ["urn:signet:cap:sign:artifact"] encodes as:
//
//	30 1E 0C 1C 75 72 6E 3A 73 69 67 6E 65 74 3A 63
//	61 70 3A 73 69 67 6E 3A 61 72 74 69 66 61 63 74
//
// TypeScript equivalent (asn1js):
//
//	new asn1js.Sequence({
//	  value: caps.map(c => new asn1js.Utf8String({ value: c }))
//	}).toBER(false)
func MarshalCapabilities(capabilities []string) ([]byte, error) {
	vals := make([]asn1.RawValue, len(capabilities))
	for i, cap := range capabilities {
		// Force UTF8String (tag 0x0C) to match the declared schema.
		// Go's default asn1.Marshal produces PrintableString (tag 0x13)
		// for ASCII-only strings, which is valid ASN.1 but violates the
		// SEQUENCE OF UTF8String schema and breaks tag-sensitive parsers
		// like asn1js used by TypeScript consumers.
		b, err := asn1.MarshalWithParams(cap, "utf8")
		if err != nil {
			return nil, err
		}
		vals[i] = asn1.RawValue{FullBytes: b}
	}
	return asn1.Marshal(vals)
}

// ParseCapabilities extracts capability URIs from a certificate's signet
// capability extension. Returns nil, nil if the extension is not present.
func ParseCapabilities(cert *x509.Certificate) ([]string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDSignetCapabilities) {
			return UnmarshalCapabilities(ext.Value)
		}
	}
	return nil, nil
}

// UnmarshalCapabilities decodes ASN.1 SEQUENCE OF UTF8String back to strings.
// This is the inverse of MarshalCapabilities and validates the interop contract.
func UnmarshalCapabilities(data []byte) ([]string, error) {
	var raw []asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after capabilities")
	}

	caps := make([]string, len(raw))
	for i, r := range raw {
		var s string
		_, err := asn1.Unmarshal(r.FullBytes, &s)
		if err != nil {
			return nil, err
		}
		caps[i] = s
	}
	return caps, nil
}
