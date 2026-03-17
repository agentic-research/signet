package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
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
	capExt, err := marshalCapabilities(capabilities)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "signet-bridge",
			Organization: []string{"Signet"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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

// marshalCapabilities encodes capability URIs as ASN.1 SEQUENCE OF UTF8String.
func marshalCapabilities(capabilities []string) ([]byte, error) {
	vals := make([]asn1.RawValue, len(capabilities))
	for i, cap := range capabilities {
		b, err := asn1.Marshal(cap)
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
			return unmarshalCapabilities(ext.Value)
		}
	}
	return nil, nil
}

// unmarshalCapabilities decodes ASN.1 SEQUENCE OF UTF8String back to strings.
func unmarshalCapabilities(data []byte) ([]string, error) {
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
