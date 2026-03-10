package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/keys"
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

	// Use a flag to track ownership transfer. If we successfully return the key to
	// the caller, we set this to true to prevent cleanup. Otherwise, defer ensures
	// the key is destroyed on any error path.
	var ownershipTransferred bool
	defer func() {
		if !ownershipTransferred {
			secPriv.Destroy()
		}
	}()

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

	// Mark ownership as transferred before returning
	ownershipTransferred = true
	return cert, certDER, secPriv, nil // Caller now owns secPriv
}

// IssueCertificateForSigner creates an X.509 certificate for code signing
// for a provided crypto.Signer with the specified validity duration.
// The certificate is issued by the master key (CA) for the signer's public key.
//
// This method is designed to work with any crypto.Signer implementation,
// including hardware-backed signers (PKCS#11, HSM) where the private key
// never leaves the secure hardware.
//
// Returns the certificate and DER bytes. The caller is responsible for
// managing the lifecycle of the provided signer.
func (ca *LocalCA) IssueCertificateForSigner(signer crypto.Signer, validityDuration time.Duration) (*x509.Certificate, []byte, error) {
	// 1. Validate inputs
	if signer == nil {
		return nil, nil, errors.New("signer cannot be nil")
	}
	if validityDuration <= 0 {
		return nil, nil, errors.New("validity duration must be positive")
	}

	// 2. Get public key from the signer
	publicKey := signer.Public()
	if publicKey == nil {
		return nil, nil, errors.New("signer returned nil public key")
	}

	// 3. Create CA (issuer) certificate template
	// This represents the master key acting as CA
	issuerTemplate := ca.CreateCACertificateTemplate()
	if issuerTemplate == nil {
		return nil, nil, errors.New("failed to create issuer template")
	}

	// 4. Create certificate template for the signer's public key
	template := ca.CreateCertificateTemplate(validityDuration)
	if template == nil {
		return nil, nil, errors.New("failed to create certificate template")
	}

	// 5. Add Subject Key Identifier (required for Git)
	template.SubjectKeyId = generateSubjectKeyID(publicKey)
	if template.SubjectKeyId == nil {
		return nil, nil, errors.New("failed to generate subject key ID (unsupported key type)")
	}

	// 6. Add Authority Key Identifier (points to master key)
	issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
	template.AuthorityKeyId = issuerTemplate.SubjectKeyId

	// 7. Issue the certificate: master key signs for signer's public key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,       // certificate being created
		issuerTemplate, // CA certificate (master key)
		publicKey,      // public key being certified (from signer)
		ca.masterKey,   // CA private key for signing
	)
	if err != nil {
		return nil, nil, err
	}

	// 8. Parse the certificate to return
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

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
		SerialNumber: serialNumber,
		Subject:      EncodeDIDAsSubject(ca.issuerDID),
		Issuer:       EncodeDIDAsSubject(ca.issuerDID),   // Self-issued
		NotBefore:    now.Add(-24 * time.Hour),           // Valid from yesterday to avoid clock skew
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		// NOTE: CA certificates should NOT have ExtKeyUsage restrictions.
		// ExtKeyUsage restricts certificate usage, which conflicts with the CA role.
		// Only end-entity certificates (ephemeral keys) should have ExtKeyUsageCodeSigning.
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
// using RFC 5280 method (1): SHA-1 hash of the public key.
// While SHA-1 has known weaknesses for collision resistance, it remains
// acceptable for SKI generation as:
// 1. SKI is not security-critical (it's just an identifier)
// 2. RFC 5280 specifically requires SHA-1 for method (1)
// 3. The attacker doesn't control both inputs (no collision attack)
func generateSubjectKeyID(publicKey crypto.PublicKey) []byte {
	var pubBytes []byte

	switch pub := publicKey.(type) {
	case ed25519.PublicKey:
		pubBytes = pub
	case *ecdsa.PublicKey:
		// For ECDSA, we need to marshal the public key to SubjectPublicKeyInfo format
		// This is the standard X.509 format for public keys
		var err error
		pubBytes, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil
		}
	default:
		// Unsupported key type
		return nil
	}

	// Use SHA-1 as specified in RFC 5280 Section 4.2.1.2 method (1)
	h := sha1.Sum(pubBytes)
	// SHA-1 produces exactly 20 bytes, no truncation needed
	return h[:]
}
