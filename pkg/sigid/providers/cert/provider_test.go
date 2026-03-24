package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestExtractIdentity_WithOIDExtensions(t *testing.T) {
	cert := createTestCert(t, "user@example.com", "github-12345", true)
	p := NewProvider()

	id, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}

	if id.Owner != "github-12345" {
		t.Errorf("Owner = %q, want %q", id.Owner, "github-12345")
	}
	if id.Issuer != "signet-authority" {
		t.Errorf("Issuer = %q, want %q", id.Issuer, "signet-authority")
	}
	if id.Machine == "" {
		t.Error("Machine fingerprint is empty")
	}
	if len(id.Machine) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("Machine fingerprint length = %d, want 64", len(id.Machine))
	}
	if id.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}
}

func TestExtractIdentity_FallbackToCN(t *testing.T) {
	cert := createTestCert(t, "user@example.com", "", false)
	p := NewProvider()

	id, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}

	if id.Owner != "user@example.com" {
		t.Errorf("Owner = %q, want %q (CN fallback)", id.Owner, "user@example.com")
	}
}

func TestExtractIdentity_NilCert(t *testing.T) {
	p := NewProvider()
	_, err := p.ExtractIdentity(nil)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestExtractContext(t *testing.T) {
	cert := createTestCert(t, "user@example.com", "github-12345", true)
	p := NewProvider()

	ctx, err := p.ExtractContext(cert)
	if err != nil {
		t.Fatalf("ExtractContext: %v", err)
	}

	if ctx.Provenance == nil {
		t.Fatal("Provenance is nil")
	}
	if ctx.Provenance.ActorPPID != "github-12345" {
		t.Errorf("ActorPPID = %q, want %q", ctx.Provenance.ActorPPID, "github-12345")
	}
	if ctx.Provenance.Issuer != "signet-authority" {
		t.Errorf("Issuer = %q, want %q", ctx.Provenance.Issuer, "signet-authority")
	}
	if ctx.Environment != nil {
		t.Error("Environment should be nil (cert doesn't carry it)")
	}
	if ctx.Boundary != nil {
		t.Error("Boundary should be nil (cert doesn't carry it)")
	}
}

func TestExtractIdentity_ECDSAP256(t *testing.T) {
	cert := createTestCertECDSA(t, "browser-user@example.com", "google-67890")
	p := NewProvider()

	id, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity (P-256): %v", err)
	}

	if id.Owner != "google-67890" {
		t.Errorf("Owner = %q, want %q", id.Owner, "google-67890")
	}
	if id.Machine == "" {
		t.Error("Machine fingerprint is empty for P-256 cert")
	}
}

func TestMachineFingerprint_DifferentKeys(t *testing.T) {
	cert1 := createTestCert(t, "user1@example.com", "user-1", true)
	cert2 := createTestCert(t, "user2@example.com", "user-2", true)
	p := NewProvider()

	id1, _ := p.ExtractIdentity(cert1)
	id2, _ := p.ExtractIdentity(cert2)

	if id1.Machine == id2.Machine {
		t.Error("different keys should produce different machine fingerprints")
	}
}

// --- test helpers ---

// testCA generates a CA keypair for signing test certs.
func testCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"rosary"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	return caCert, caPriv
}

func createTestCert(t *testing.T, email, subject string, withOIDs bool) *x509.Certificate {
	t.Helper()
	caCert, caPriv := testCA(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"rosary"},
		},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if withOIDs && subject != "" {
		subjectDER, _ := asn1.Marshal(subject)
		timeDER, _ := asn1.Marshal(now.Format(time.RFC3339))
		template.ExtraExtensions = []pkix.Extension{
			{Id: oidSubject, Value: subjectDER},
			{Id: oidIssuanceTime, Value: timeDER},
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func createTestCertECDSA(t *testing.T, email, subject string) *x509.Certificate {
	t.Helper()
	caCert, caPriv := testCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	subjectDER, _ := asn1.Marshal(subject)
	timeDER, _ := asn1.Marshal(now.Format(time.RFC3339))

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"rosary"},
		},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: oidSubject, Value: subjectDER},
			{Id: oidIssuanceTime, Value: timeDER},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
