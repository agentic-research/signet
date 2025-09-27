package x509

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"time"
)

// LocalCA provides the logic to issue self-signed, short-lived X.509 certificates
// from a master key for the MVP. The certificate's subject will be the issuer's DID.
type LocalCA struct {
	// masterKey is the master signing key
	masterKey crypto.Signer
	
	// issuerDID is the DID that will be used as the certificate subject
	issuerDID string
}

// NewLocalCA creates a new Local CA with the given master key and DID
func NewLocalCA(masterKey crypto.Signer, issuerDID string) *LocalCA {
	return &LocalCA{
		masterKey: masterKey,
		issuerDID: issuerDID,
	}
}

// IssueCodeSigningCertificate creates a self-signed X.509 certificate
// for code signing with the specified validity duration
func (ca *LocalCA) IssueCodeSigningCertificate(validityDuration time.Duration) (*x509.Certificate, []byte, error) {
	// 1. Generate ephemeral key pair for the certificate
	ephemeralPub, ephemeralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// 2. Create certificate template
	template := ca.CreateCertificateTemplate(validityDuration)
	if template == nil {
		return nil, nil, errors.New("failed to create certificate template")
	}
	
	// 3. Add Subject Key Identifier (required for Git)
	template.SubjectKeyId = generateSubjectKeyID(ephemeralPub)
	
	// 4. Self-sign the certificate with master key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template, // self-signed
		ephemeralPub,
		ca.masterKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// 5. Parse the certificate to return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// Store the private key in the certificate's extensions (for signing)
	// Note: In production, return the private key separately
	_ = ephemeralPriv // We'll need to return this for actual signing

	return cert, certDER, nil
}

// IssueEphemeralCertificate creates a self-signed ephemeral certificate
// with the given public key and validity duration
func (ca *LocalCA) IssueEphemeralCertificate(publicKey crypto.PublicKey, validityDuration time.Duration) (*x509.Certificate, []byte, error) {
	template := ca.CreateCertificateTemplate(validityDuration)
	if template == nil {
		return nil, nil, errors.New("failed to create certificate template")
	}
	
	// Add Subject Key Identifier (required for Git)
	template.SubjectKeyId = generateSubjectKeyID(publicKey)
	
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template, // self-signed
		publicKey,
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

// CreateCertificateTemplate creates a basic X.509 certificate template
// with the CA's DID as subject
func (ca *LocalCA) CreateCertificateTemplate(validityDuration time.Duration) *x509.Certificate {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		// If we can't generate a serial number, we can't create a certificate
		return nil
	}
	
	now := time.Now()
	
	// Parse DID as URI for SAN
	didURI, _ := url.Parse(ca.issuerDID)
	
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      EncodeDIDAsSubject(ca.issuerDID),
		NotBefore:    now,
		NotAfter:     now.Add(validityDuration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{didURI},
		IsCA:         false,
	}
}

// GenerateSerialNumber generates a random serial number for a certificate
func GenerateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// EncodeDIDAsSubject encodes a DID as an X.509 subject
func EncodeDIDAsSubject(did string) pkix.Name {
	// Use short CN if DID is too long (> 64 bytes)
	cn := did
	if len(did) > 64 {
		cn = "Signet Ephemeral"
	}
	return pkix.Name{
		CommonName: cn,
		Organization: []string{"Signet"},
	}
}

// generateSubjectKeyID generates a Subject Key Identifier for a public key
// Uses SHA-1 hash as per RFC 5280 (method 1)
func generateSubjectKeyID(publicKey crypto.PublicKey) []byte {
	var pubBytes []byte
	
	switch pub := publicKey.(type) {
	case ed25519.PublicKey:
		pubBytes = pub
	default:
		// For other key types, we'd need to marshal them appropriately
		// For MVP, we only support Ed25519
		return nil
	}
	
	h := sha1.Sum(pubBytes)
	return h[:]
}