package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
)

func TestVerifyCert_Valid(t *testing.T) {
	certPath, caPath := createTestCertFiles(t, "user@example.com", "github-12345", 24*time.Hour)

	result, err := verifyCert(certPath, caPath)
	if err != nil {
		t.Fatalf("verifyCert: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid cert, got invalid: %s", result.Reason)
	}
	if result.Subject != "user@example.com" {
		t.Errorf("Subject = %q, want %q", result.Subject, "user@example.com")
	}
	if result.Owner != "github-12345" {
		t.Errorf("Owner = %q, want %q", result.Owner, "github-12345")
	}
	if result.Issuer != "signet-authority" {
		t.Errorf("Issuer = %q, want %q", result.Issuer, "signet-authority")
	}
}

func TestVerifyCert_Expired(t *testing.T) {
	certPath, caPath := createTestCertFiles(t, "expired@example.com", "user-1", -1*time.Hour)

	result, err := verifyCert(certPath, caPath)
	if err != nil {
		t.Fatalf("verifyCert: %v", err)
	}
	if result.Valid {
		t.Error("expected invalid for expired cert")
	}
}

func TestVerifyCert_WrongCA(t *testing.T) {
	certPath, _ := createTestCertFiles(t, "user@example.com", "user-1", 24*time.Hour)

	// Create a different CA
	_, otherCAPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: "other-authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	otherCADER, _ := x509.CreateCertificate(rand.Reader, otherCATmpl, otherCATmpl, otherCAPriv.Public(), otherCAPriv)
	otherCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCADER})

	otherCAPath := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(otherCAPath, otherCAPEM, 0o644); err != nil {
		t.Fatalf("write other CA: %v", err)
	}

	result, err := verifyCert(certPath, otherCAPath)
	if err != nil {
		t.Fatalf("verifyCert: %v", err)
	}
	if result.Valid {
		t.Error("expected invalid for wrong CA")
	}
}

func TestVerifyCert_MissingFile(t *testing.T) {
	_, err := verifyCert("/nonexistent/cert.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --- test helper ---

func createTestCertFiles(t *testing.T, email, ownerID string, validity time.Duration) (certPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	// Generate CA
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"rosary"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Generate client cert (P-256)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	now := time.Now()
	subjectDER, _ := asn1.Marshal(ownerID)

	clientTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: email, Organization: []string{"rosary"}},
		NotBefore:      now,
		NotAfter:       now.Add(validity),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{email},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier(sigid.OIDSubject), Value: subjectDER},
		},
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caPriv)
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	certPath = filepath.Join(dir, "cert.pem")
	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, clientPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	return certPath, caPath
}
