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

	"github.com/jamestexas/signet/pkg/crypto/keys"
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

// IssueCodeSigningCertificate creates an X.509 certificate
// for code signing with the specified validity duration
// The certificate is issued by the master key (CA) for an ephemeral key
// Returns the certificate, DER bytes, and the ephemeral private key
//
// SECURITY WARNING: The returned private key is NOT automatically zeroed.
// Callers MUST explicitly zero the key when done using keys.ZeroizePrivateKey:
//
//	cert, der, ephemeralKey, err := ca.IssueCodeSigningCertificate(duration)
//	if err != nil { return err }
//	defer keys.ZeroizePrivateKey(ephemeralKey)
//
// Deprecated: Use IssueCodeSigningCertificateSecure for automatic key cleanup.
func (ca *LocalCA) IssueCodeSigningCertificate(validityDuration time.Duration) (*x509.Certificate, []byte, ed25519.PrivateKey, error) {
	// 1. Generate ephemeral key pair for the certificate
	ephemeralPub, ephemeralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Create CA (issuer) certificate template
	// This represents the master key acting as CA
	issuerTemplate := ca.CreateCACertificateTemplate()
	if issuerTemplate == nil {
		return nil, nil, nil, errors.New("failed to create issuer template")
	}

	// 3. Create certificate template for the ephemeral key
	template := ca.CreateCertificateTemplate(validityDuration)
	if template == nil {
		return nil, nil, nil, errors.New("failed to create certificate template")
	}

	// 4. Add Subject Key Identifier (required for Git)
	template.SubjectKeyId = generateSubjectKeyID(ephemeralPub)

	// 5. Add Authority Key Identifier (points to master key)
	issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
	template.AuthorityKeyId = issuerTemplate.SubjectKeyId

	// 6. Issue the certificate: master key signs for ephemeral key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,       // certificate being created
		issuerTemplate, // CA certificate (master key)
		ephemeralPub,   // public key being certified
		ca.masterKey,   // CA private key for signing
	)
	if err != nil {
		return nil, nil, nil, err
	}

	// 7. Parse the certificate to return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, certDER, ephemeralPriv, nil
}

// IssueCodeSigningCertificateSecure creates an X.509 certificate
// for code signing with the specified validity duration.
// The certificate is issued by the master key (CA) for an ephemeral key.
// Returns the certificate, DER bytes, and a secure wrapper for the ephemeral private key.
//
// The returned SecurePrivateKey automatically manages memory cleanup.
// Callers MUST call Destroy() when done, typically with defer:
//
//	cert, der, secKey, err := ca.IssueCodeSigningCertificateSecure(duration)
//	if err != nil { return err }
//	defer secKey.Destroy()
func (ca *LocalCA) IssueCodeSigningCertificateSecure(validityDuration time.Duration) (*x509.Certificate, []byte, *keys.SecurePrivateKey, error) {
	// 1. Generate ephemeral key pair with secure wrapper
	ephemeralPub, secPriv, err := keys.GenerateSecureKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	// Note: Caller is responsible for calling secPriv.Destroy()

	// 2. Create CA (issuer) certificate template
	// This represents the master key acting as CA
	issuerTemplate := ca.CreateCACertificateTemplate()
	if issuerTemplate == nil {
		secPriv.Destroy() // Clean up on error
		return nil, nil, nil, errors.New("failed to create issuer template")
	}

	// 3. Create certificate template for the ephemeral key
	template := ca.CreateCertificateTemplate(validityDuration)
	if template == nil {
		secPriv.Destroy() // Clean up on error
		return nil, nil, nil, errors.New("failed to create certificate template")
	}

	// 4. Add Subject Key Identifier (required for Git)
	template.SubjectKeyId = generateSubjectKeyID(ephemeralPub)

	// 5. Add Authority Key Identifier (points to master key)
	issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
	template.AuthorityKeyId = issuerTemplate.SubjectKeyId

	// 6. Issue the certificate: master key signs for ephemeral key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,       // certificate being created
		issuerTemplate, // CA certificate (master key)
		ephemeralPub,   // public key being certified
		ca.masterKey,   // CA private key for signing
	)
	if err != nil {
		secPriv.Destroy() // Clean up on error
		return nil, nil, nil, err
	}

	// 7. Parse the certificate to return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		secPriv.Destroy() // Clean up on error
		return nil, nil, nil, err
	}

	return cert, certDER, secPriv, nil
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

// CreateCACertificateTemplate creates a template for the CA (master key) certificate
func (ca *LocalCA) CreateCACertificateTemplate() *x509.Certificate {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil
	}

	// CA certificate has a long validity (10 years for the master key)
	now := time.Now()

	// Parse DID as URI for SAN
	didURI, _ := url.Parse(ca.issuerDID)

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               EncodeDIDAsSubject(ca.issuerDID),
		Issuer:                EncodeDIDAsSubject(ca.issuerDID),   // Self-issued
		NotBefore:             now.Add(-24 * time.Hour),           // Valid from yesterday to avoid clock skew
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:                  []*url.URL{didURI},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
}

// CreateCertificateTemplate creates a basic X.509 certificate template
// for an ephemeral certificate
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
		SerialNumber:          serialNumber,
		Subject:               EncodeDIDAsSubject(ca.issuerDID),
		Issuer:                EncodeDIDAsSubject(ca.issuerDID), // Will be overridden by CA issuer
		NotBefore:             now,
		NotAfter:              now.Add(validityDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:                  []*url.URL{didURI},
		IsCA:                  false,
		BasicConstraintsValid: true,
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
		CommonName:   cn,
		Organization: []string{"Signet"},
	}
}

// IssueClientCertificate creates a client identity certificate
// signed by the master key for the provided device public key
func (ca *LocalCA) IssueClientCertificate(template *x509.Certificate, devicePublicKey ed25519.PublicKey) (*x509.Certificate, error) {
	// Create CA (issuer) certificate template
	issuerTemplate := ca.CreateCACertificateTemplate()
	if issuerTemplate == nil {
		return nil, errors.New("failed to create issuer template")
	}

	// Add Subject Key Identifier for the device key
	template.SubjectKeyId = generateSubjectKeyID(devicePublicKey)

	// Add Authority Key Identifier (points to master key)
	issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
	template.AuthorityKeyId = issuerTemplate.SubjectKeyId

	// Issue the certificate: master key signs for device key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,        // certificate being created
		issuerTemplate,  // CA certificate (master key)
		devicePublicKey, // public key being certified
		ca.masterKey,    // CA private key for signing
	)
	if err != nil {
		return nil, err
	}

	// Parse the certificate to return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
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
