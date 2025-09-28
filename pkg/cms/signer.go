package cms

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// SignData creates a detached CMS/PKCS#7 signature using the proper pkcs7 library
// This aligns with ADR-003: Use external libraries for standards implementation
func SignData(data []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	// Create a new SignedData structure
	signedData, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	// Set to create detached signature (no embedded content)
	signedData.Detach()

	// Add the signer with certificate
	if err := signedData.AddSigner(cert, signer, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("failed to add signer: %w", err)
	}

	// Finish and get the encoded CMS/PKCS#7 structure
	return signedData.Finish()
}

// VerifySignature verifies a CMS/PKCS#7 signature
func VerifySignature(signature []byte, data []byte) error {
	// Parse the PKCS#7 structure
	p7, err := pkcs7.Parse(signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Set the content for detached signature verification
	p7.Content = data

	// Verify the signature
	// Note: This will verify against certificates in the signature
	// For self-signed certs, we may need to add trust roots
	if err := p7.Verify(); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// GetSignerCertificate extracts the signer's certificate from a CMS/PKCS#7 signature
func GetSignerCertificate(signature []byte) (*x509.Certificate, error) {
	p7, err := pkcs7.Parse(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in signature")
	}

	// Return the first certificate (typically the signer's cert)
	return p7.Certificates[0], nil
}