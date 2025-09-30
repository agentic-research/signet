package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	attestx509 "github.com/jamestexas/signet/pkg/attest/x509"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

// Authority manages certificate issuance for the Signet Authority service
type Authority struct {
	ca     *attestx509.LocalCA
	logger *slog.Logger
	config *Config
}

// NewAuthority creates a new Authority instance
func NewAuthority(config *Config, logger *slog.Logger) (*Authority, error) {
	// Load the PEM-encoded Ed25519 private key from the specified path
	keyData, err := os.ReadFile(config.AuthorityMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read master key: %w", err)
	}

	// Parse the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var ed25519Key ed25519.PrivateKey

	// Try to parse as PKCS8 first (OpenSSL format)
	if privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		ed25519Key, ok = privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
	} else if block.Type == "ED25519 PRIVATE KEY" && len(block.Bytes) == ed25519.SeedSize {
		// Try signet-commit format (seed only)
		ed25519Key = ed25519.NewKeyFromSeed(block.Bytes)
	} else {
		return nil, fmt.Errorf("failed to parse private key: unsupported format")
	}

	// Create a keys.Signer from the private key
	signer := keys.NewEd25519Signer(ed25519Key)

	// Create a new LocalCA with the signer and issuer DID
	// Using a standard DID for the Signet Authority
	issuerDID := "did:signet:authority"
	ca := attestx509.NewLocalCA(signer, issuerDID)

	return &Authority{
		ca:     ca,
		logger: logger,
		config: config,
	}, nil
}

// Claims represents simplified OIDC claims
type Claims struct {
	Email   string `json:"email"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
}

// MintClientCertificate creates a new client identity certificate
// It takes the verified OIDC claims and the user's device public key
// and returns a PEM-encoded client identity certificate
func (a *Authority) MintClientCertificate(
	claims Claims,
	devicePublicKey ed25519.PublicKey,
) ([]byte, error) {
	// Log the certificate issuance attempt
	a.logger.Info("Minting client certificate",
		"email", claims.Email,
		"subject", claims.Subject,
	)

	// Calculate certificate validity
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(a.config.CertificateValidity) * time.Hour)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:         claims.Email,
			Organization:       []string{"Signet Authority"},
			OrganizationalUnit: []string{"Client Certificates"},
		},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:         false,
		MaxPathLen:   -1,
		SubjectKeyId: devicePublicKey[:20], // First 20 bytes as SKI

		// Add SAN extension with email
		EmailAddresses: []string{claims.Email},

		// Add custom extensions for Signet-specific data
		ExtraExtensions: []pkix.Extension{
			{
				// OID for Signet Subject (1.3.6.1.4.1.99999.1.1)
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1, 1},
				Value: []byte(claims.Subject),
			},
			{
				// OID for Signet Issuance Time (1.3.6.1.4.1.99999.1.2)
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1, 2},
				Value: []byte(notBefore.Format(time.RFC3339)),
			},
		},
	}

	// Issue the certificate using the device's public key
	cert, err := a.ca.IssueClientCertificate(template, devicePublicKey)
	if err != nil {
		a.logger.Error("Failed to issue certificate",
			"email", claims.Email,
			"error", err,
		)
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	// PEM-encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	a.logger.Info("Successfully minted client certificate",
		"email", claims.Email,
		"serial", cert.SerialNumber,
		"expires", notAfter,
	)

	return certPEM, nil
}
