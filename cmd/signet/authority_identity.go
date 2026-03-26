package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
	"github.com/agentic-research/signet/pkg/crypto/keys"
	oidcprovider "github.com/agentic-research/signet/pkg/oidc"
	"github.com/agentic-research/signet/pkg/policy"
	"github.com/agentic-research/signet/pkg/sigid"
)

type Authority struct {
	ca               *attestx509.LocalCA
	publicKey        ed25519.PublicKey // trust anchor for policy bundle verification
	logger           *slog.Logger
	config           *AuthorityConfig
	providerRegistry *oidcprovider.Registry
}

func newAuthority(config *AuthorityConfig, logger *slog.Logger, registry *oidcprovider.Registry) (*Authority, error) {
	// Load the PEM-encoded Ed25519 private key
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

	// Note: Master key remains in memory for server lifetime
	// This is a security tradeoff for performance - the key is needed for every
	// certificate issuance operation. For production use, consider implementing
	// key refresh or loading on-demand with caching.

	// Create a keys.Signer from the private key
	signer := keys.NewEd25519Signer(ed25519Key)

	// Create a new LocalCA with the signer and issuer DID
	issuerDID := "did:signet:authority"
	ca := attestx509.NewLocalCA(signer, issuerDID)

	return &Authority{
		ca:               ca,
		publicKey:        ed25519Key.Public().(ed25519.PublicKey),
		logger:           logger,
		config:           config,
		providerRegistry: registry,
	}, nil
}

// Claims represents simplified OIDC claims
type Claims struct {
	Email   string `json:"email"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
}

// AgentIdentity holds optional agent-specific identity fields for cert minting.
// When non-nil, the cert represents an agent rather than a human.
type AgentIdentity struct {
	Name  string // e.g. "dev-agent", "staging-agent"
	Scope string // e.g. "repo:signet" or "repo:rosary,contents:write"
}

func (a *Authority) mintClientCertificate(claims Claims, devicePublicKey crypto.PublicKey) ([]byte, error) {
	return a.mintClientCertificateWithAgent(claims, devicePublicKey, nil)
}

func (a *Authority) mintClientCertificateWithAgent(claims Claims, devicePublicKey crypto.PublicKey, agent *AgentIdentity) ([]byte, error) {
	a.logger.Info("Minting client certificate",
		"email", claims.Email,
		"subject", claims.Subject,
		"agent", agent,
	)

	// Calculate certificate validity, capped to max
	notBefore := time.Now()
	validity := time.Duration(a.config.CertificateValidity) * time.Hour
	maxHours := a.config.MaxCertValidityHours
	if maxHours <= 0 {
		maxHours = 24
	}
	maxValidity := time.Duration(maxHours) * time.Hour
	if validity > maxValidity {
		validity = maxValidity
	}
	notAfter := notBefore.Add(validity)

	// Create certificate template
	serial, err := attestx509.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}
	// Determine CN and OU based on whether this is an agent or human cert
	cn := claims.Email
	ou := "Client Certificates"
	if agent != nil && agent.Name != "" {
		cn = fmt.Sprintf("agent:%s", agent.Name)
		ou = "Agent Certificates"
	}

	extensions := []pkix.Extension{
		{
			// Signet Subject OID — canonical source: pkg/sigid/identity.go
			Id:    asn1.ObjectIdentifier(sigid.OIDSubject),
			Value: []byte(claims.Subject),
		},
		{
			// Signet Issuance Time OID — canonical source: pkg/sigid/identity.go
			Id:    asn1.ObjectIdentifier(sigid.OIDIssuanceTime),
			Value: []byte(notBefore.Format(time.RFC3339)),
		},
	}

	// Add agent-specific extensions (scope requires a named agent)
	if agent != nil && agent.Name != "" {
		extensions = append(extensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier(sigid.OIDAgentName),
			Value: []byte(agent.Name),
		})
		if agent.Scope != "" {
			extensions = append(extensions, pkix.Extension{
				Id:    asn1.ObjectIdentifier(sigid.OIDScope),
				Value: []byte(agent.Scope),
			})
		}
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Signet Authority"},
			OrganizationalUnit: []string{ou},
		},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:            false,
		MaxPathLen:      -1,
		EmailAddresses:  []string{claims.Email},
		ExtraExtensions: extensions,
	}

	// Issue the certificate (SubjectKeyId computed by IssueClientCertificate from the public key)
	cert, err := a.ca.IssueClientCertificate(template, devicePublicKey)
	if err != nil {
		a.logger.Error("Failed to issue certificate", "email", claims.Email, "error", err)
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

// maxPublicKeyBytes is the upper bound on decoded public key size.
// Ed25519 raw = 32 bytes, SPKI Ed25519 = 44 bytes, SPKI P-256 = 91 bytes.
// 256 bytes allows generous headroom while blocking ASN.1 parsing DoS.
const maxPublicKeyBytes = 256

// parsePublicKeyBytes interprets raw bytes as a public key. It tries:
//  1. Ed25519 (exactly 32 bytes → raw Ed25519 public key)
//  2. SPKI/DER (PKIX-encoded public key — works for ECDSA, Ed25519, etc.)
//
// This allows callers to provide either a raw Ed25519 key (legacy)
// or a standard SPKI-encoded key (browser WebCrypto, OpenSSL).
func parsePublicKeyBytes(data []byte) (crypto.PublicKey, error) {
	if len(data) > maxPublicKeyBytes {
		return nil, fmt.Errorf("key too large (%d bytes, max %d)", len(data), maxPublicKeyBytes)
	}

	if len(data) == ed25519.PublicKeySize {
		// Reject all-zero Ed25519 keys
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil, fmt.Errorf("rejected all-zero Ed25519 key")
		}
		return ed25519.PublicKey(data), nil
	}

	// Try SPKI/DER (SubjectPublicKeyInfo)
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("unsupported key format (not Ed25519 raw or SPKI/DER): %w", err)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		// Validate by attempting ECDH conversion (rejects point-at-infinity / invalid curve points)
		if _, err := k.ECDH(); err != nil {
			return nil, fmt.Errorf("rejected invalid ECDSA key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T (expected Ed25519 or ECDSA)", pub)
	}
}

// handleCABundle serves the CA certificate as PEM at /.well-known/ca-bundle.pem.
// This is the trust anchor URL that MCP server operators add to their config.
// Cached in memory — the CA cert doesn't change during server lifetime.
func handleCABundle(authority *Authority) http.HandlerFunc {
	// Generate once at startup (CA cert is static)
	caPEM, err := authority.ca.CACertPEM()
	if err != nil {
		authority.logger.Error("Failed to generate CA certificate PEM", "error", err)
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CA certificate unavailable", http.StatusInternalServerError)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "public, max-age=3600") // 1h cache
		_, _ = w.Write(caPEM)
	}
}

// noopBundleFetcher always returns an error, keeping the PolicyChecker in bootstrap mode
// until a real bundle server is configured. This is the safe default — bootstrap mode
// allows all subjects, matching pre-policy behavior.
type noopBundleFetcher struct{}

func (f *noopBundleFetcher) Fetch(_ context.Context) (*policy.TrustPolicyBundle, error) {
	return nil, fmt.Errorf("no policy bundle server configured")
}
