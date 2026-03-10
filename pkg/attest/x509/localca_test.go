package x509

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"

	"github.com/agentic-research/go-cms/pkg/cms"
)

// TestCertificateChainValidation tests that certificates issued by LocalCA
// can be validated in a proper certificate chain.
//
// This is a regression test for the bug where CA certificates had ExtKeyUsage
// restrictions that prevented chain validation.
//
// Bug: CA certificate template included ExtKeyUsage: [CodeSigning], which is
// incompatible with the CA role. CA certificates should NOT have ExtKeyUsage
// restrictions because they need to sign other certificates (not just code).
func TestCertificateChainValidation(t *testing.T) {
	// 1. Create master key and LocalCA
	_, masterPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	ca := NewLocalCA(masterPriv, "did:key:test-signet")

	// 2. Issue an ephemeral certificate for code signing
	cert, _, secKey, err := ca.IssueCodeSigningCertificateSecure(5 * time.Minute)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	defer secKey.Destroy()

	// 3. Create test data and sign it with CMS
	testData := []byte("test commit data for signature verification")
	signature, err := cms.SignData(testData, cert, ed25519.PrivateKey(secKey.Key()))
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// 4. Create a CA certificate to use as the trust root
	// This simulates what a verifier would do - they trust the master key (CA)
	// and need to verify a signature from an ephemeral certificate signed by that CA
	caTemplate := ca.CreateCACertificateTemplate()
	if caTemplate == nil {
		t.Fatal("Failed to create CA template")
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(
		nil,
		caTemplate,
		caTemplate,
		ca.masterKey.Public(),
		ca.masterKey,
	)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// 5. Verify the CMS signature using the CA cert as a trusted root
	// This should succeed if the certificate chain is valid
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	verifiedCerts, err := cms.Verify(signature, testData, cms.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})

	// Regression test: Verify CA cert properly validates chains (no ExtKeyUsage conflicts)
	// Previously failed when CA cert incorrectly had ExtKeyUsage: [CodeSigning]
	if err != nil {
		t.Fatalf("Certificate chain validation failed: %v\n"+
			"This indicates the CA certificate has incompatible ExtKeyUsage restrictions.\n"+
			"CA certificates should NOT have ExtKeyUsage set, as it conflicts with their role.", err)
	}

	// Verify we got the ephemeral certificate back
	if len(verifiedCerts) == 0 {
		t.Fatal("No certificates returned from verification")
	}

	// The first cert should be the signer (ephemeral cert)
	if !verifiedCerts[0].Equal(cert) {
		t.Error("Verified certificate does not match the signer certificate")
	}

	t.Log("✓ Certificate chain validation successful")
}

// TestCATemplateShouldNotHaveExtKeyUsage verifies that CA certificate
// templates do not include ExtKeyUsage restrictions.
func TestCATemplateShouldNotHaveExtKeyUsage(t *testing.T) {
	_, masterPriv, _ := ed25519.GenerateKey(nil)
	ca := NewLocalCA(masterPriv, "did:key:test")

	template := ca.CreateCACertificateTemplate()
	if template == nil {
		t.Fatal("Failed to create CA template")
	}

	// CA certificate should be marked as CA
	if !template.IsCA {
		t.Error("CA template should have IsCA=true")
	}

	// CA certificate should have CertSign key usage
	if template.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA template should have KeyUsageCertSign")
	}

	// THIS IS THE CRITICAL CHECK: CA certificates should NOT have ExtKeyUsage
	// because ExtKeyUsage restricts the certificate's usage, which conflicts
	// with the CA role of signing other certificates
	if len(template.ExtKeyUsage) > 0 {
		t.Errorf("CA template should NOT have ExtKeyUsage restrictions, but has: %v\n"+
			"ExtKeyUsage restricts certificate usage and conflicts with CA role.\n"+
			"Only end-entity certificates should have ExtKeyUsage restrictions.",
			template.ExtKeyUsage)
	}
}

// TestEndEntityTemplateShouldHaveCodeSigningExtKeyUsage verifies that
// end-entity (ephemeral) certificates DO have the CodeSigning ExtKeyUsage.
func TestEndEntityTemplateShouldHaveCodeSigningExtKeyUsage(t *testing.T) {
	_, masterPriv, _ := ed25519.GenerateKey(nil)
	ca := NewLocalCA(masterPriv, "did:key:test")

	template := ca.CreateCertificateTemplate(5 * time.Minute)
	if template == nil {
		t.Fatal("Failed to create certificate template")
	}

	// End-entity certificate should NOT be marked as CA
	if template.IsCA {
		t.Error("End-entity template should have IsCA=false")
	}

	// End-entity certificate SHOULD have ExtKeyUsage for code signing
	if len(template.ExtKeyUsage) == 0 {
		t.Error("End-entity template should have ExtKeyUsage")
	}

	hasCodeSigning := false
	for _, usage := range template.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}

	if !hasCodeSigning {
		t.Error("End-entity template should have ExtKeyUsageCodeSigning")
	}
}
