package x509

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestIssueBridgeCertificate(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test-bridge")

	ephPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caps := []string{
		"urn:signet:cap:sign:artifact",
		"urn:signet:cap:attest:build:github",
	}

	cert, der, err := ca.IssueBridgeCertificate(ephPub, caps, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueBridgeCertificate failed: %v", err)
	}
	if cert == nil || len(der) == 0 {
		t.Fatal("expected non-nil cert and non-empty DER")
	}

	// Bridge cert is an intermediate CA with MaxPathLen 0
	if !cert.IsCA {
		t.Error("bridge cert should be CA")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true")
	}

	// Subject
	if cert.Subject.CommonName != "signet-bridge" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "signet-bridge")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Signet" {
		t.Errorf("O = %v, want [Signet]", cert.Subject.Organization)
	}
}

func TestBridgeCertCapabilityRoundTrip(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test-bridge")

	ephPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caps := []string{
		"urn:signet:cap:sign:artifact",
		"urn:signet:cap:read:log",
		"urn:signet:cap:attest:build:github:main",
	}

	cert, _, err := ca.IssueBridgeCertificate(ephPub, caps, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseCapabilities(cert)
	if err != nil {
		t.Fatalf("ParseCapabilities failed: %v", err)
	}
	if len(parsed) != len(caps) {
		t.Fatalf("got %d capabilities, want %d", len(parsed), len(caps))
	}
	for i, c := range caps {
		if parsed[i] != c {
			t.Errorf("cap[%d] = %q, want %q", i, parsed[i], c)
		}
	}
}

func TestBridgeCertEmptyCapabilities(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test-bridge")

	ephPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := ca.IssueBridgeCertificate(ephPub, []string{}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseCapabilities(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(parsed))
	}
}

func TestBridgeCertChainValidation(t *testing.T) {
	// Master key = root CA
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test-bridge")

	// Bridge cert (intermediate CA, MaxPathLen 0)
	bridgePub, bridgePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bridgeCert, _, err := ca.IssueBridgeCertificate(
		bridgePub,
		[]string{"urn:signet:cap:sign:artifact"},
		10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Issue an end-entity cert signed by the bridge key
	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial, err := GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               EncodeDIDAsSubject("did:key:leaf-ephemeral"),
		NotBefore:             now,
		NotAfter:              now.Add(2 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          generateSubjectKeyID(leafPub),
		AuthorityKeyId:        bridgeCert.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, bridgeCert, leafPub, bridgePriv)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Build root CA cert for verification
	caTemplate := ca.CreateCACertificateTemplate()
	caTemplate.SubjectKeyId = generateSubjectKeyID(masterPriv.Public())
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, masterPriv.Public(), masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(bridgeCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestBridgeCertInvalidInputs(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test")

	ephPub, _, _ := ed25519.GenerateKey(rand.Reader)

	if _, _, err := ca.IssueBridgeCertificate(nil, nil, time.Minute); err == nil {
		t.Error("expected error for nil public key")
	}
	if _, _, err := ca.IssueBridgeCertificate(ephPub, nil, 0); err == nil {
		t.Error("expected error for zero validity")
	}
	if _, _, err := ca.IssueBridgeCertificate(ephPub, nil, -time.Minute); err == nil {
		t.Error("expected error for negative validity")
	}
}

func TestParseCapabilitiesNoCertExtension(t *testing.T) {
	// A cert without the capability extension should return nil, nil
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test")

	ephPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cert, _, err := ca.IssueEphemeralCertificate(ephPub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	caps, err := ParseCapabilities(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caps != nil {
		t.Errorf("expected nil capabilities, got %v", caps)
	}
}
