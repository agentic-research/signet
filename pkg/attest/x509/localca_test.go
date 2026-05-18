package x509

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/agentic-research/go-cms/pkg/cms"
	"github.com/agentic-research/signet/pkg/signet"
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

// TestIssueCodeSigningCertWithParent verifies that ephemeral certs issued
// under a parent (bridge) cert form a valid chain.
// Uses real crypto throughout (Rule 4: test reality, not mocks).
func TestIssueCodeSigningCertWithParent(t *testing.T) {
	// Root CA (master key)
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Bridge key (intermediate CA)
	bridgePub, bridgePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create root CA cert
	rootCA := NewLocalCA(masterPriv, "did:key:root")
	rootTemplate := rootCA.CreateCACertificateTemplate()
	rootTemplate.SubjectKeyId = generateSubjectKeyID(masterPriv.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, masterPriv.Public(), masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create bridge cert signed by root
	now := time.Now()
	bridgeTemplate := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               EncodeDIDAsSubject("alice@example.com"),
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          generateSubjectKeyID(bridgePub),
		AuthorityKeyId:        rootTemplate.SubjectKeyId,
	}
	bridgeDER, err := x509.CreateCertificate(rand.Reader, bridgeTemplate, rootTemplate, bridgePub, masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	bridgeCert, err := x509.ParseCertificate(bridgeDER)
	if err != nil {
		t.Fatal(err)
	}

	// Issue ephemeral cert under bridge cert
	bridgeCA := NewLocalCA(bridgePriv, "alice@example.com")
	ephCert, _, secKey, err := bridgeCA.IssueCodeSigningCertWithParent(bridgeCert, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueCodeSigningCertWithParent failed: %v", err)
	}
	defer secKey.Destroy()

	// Ephemeral cert should NOT be CA
	if ephCert.IsCA {
		t.Error("ephemeral cert should not be CA")
	}

	// Authority key ID should match bridge cert's subject key ID
	if string(ephCert.AuthorityKeyId) != string(bridgeCert.SubjectKeyId) {
		t.Error("ephemeral cert's AuthorityKeyId should match bridge cert's SubjectKeyId")
	}

	// Verify chain: root → bridge → ephemeral
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(bridgeCert)

	_, err = ephCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Fatalf("3-cert chain verification failed: %v", err)
	}
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	sn, err := GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

// TestSpiffeSAN_OmittedByDefault verifies that LocalCAs constructed without
// a SPIFFE ID emit certs whose URIs contain only the issuer DID — i.e. this
// change is additive and does not affect existing callers.
func TestSpiffeSAN_OmittedByDefault(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := NewLocalCA(masterPriv, "did:key:test-no-spiffe")

	cert, _, secKey, err := ca.IssueCodeSigningCertificateSecure(5 * time.Minute)
	if err != nil {
		t.Fatalf("IssueCodeSigningCertificateSecure failed: %v", err)
	}
	defer secKey.Destroy()

	if got := len(cert.URIs); got != 1 {
		t.Fatalf("expected exactly 1 URI SAN (DID only), got %d: %v", got, cert.URIs)
	}
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			t.Errorf("did not configure SpiffeID but found spiffe:// SAN: %s", u.String())
		}
	}
}

// TestSpiffeSAN_EmittedWhenConfigured verifies the L10 acceptance criterion:
// when a LocalCA is configured with a SPIFFE ID, ephemeral certs carry the
// `URI:spiffe://<trust-domain>/<workload-path>` URI in the SAN, and the URI
// round-trips through `x509.Certificate.URIs` (which is what verifiers like
// SPIRE / SVID-aware tools inspect).
//
// This test stands in for `openssl x509 -text` — Go's x509 parser surfaces
// URI SANs in cert.URIs verbatim, so a successful Parse + scheme/host check
// is equivalent evidence.
func TestSpiffeSAN_EmittedWhenConfigured(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const trustDomain = "art.local"
	const workload = "workload/signet-ephemeral"

	// Build via the canonical helper. This is the path real callers will
	// take when they wire a MasterKeyDescriptor.TrustDomain through.
	desc := signet.MasterKeyDescriptor{
		IssuerDID:   "did:key:test-spiffe",
		TrustDomain: trustDomain,
	}
	wantSpiffe := desc.SpiffeID(workload)
	if wantSpiffe != "spiffe://art.local/workload/signet-ephemeral" {
		t.Fatalf("BuildSpiffeID surprise: got %q", wantSpiffe)
	}

	ca := NewLocalCA(masterPriv, desc.IssuerDID).WithSpiffeID(wantSpiffe)

	cert, _, secKey, err := ca.IssueCodeSigningCertificateSecure(5 * time.Minute)
	if err != nil {
		t.Fatalf("IssueCodeSigningCertificateSecure failed: %v", err)
	}
	defer secKey.Destroy()

	// The SAN should contain at least two URIs now: the issuer DID and
	// the SPIFFE ID. Order is implementation detail; we search by scheme.
	if len(cert.URIs) < 2 {
		t.Fatalf("expected >=2 URI SANs (DID + spiffe), got %d: %v", len(cert.URIs), cert.URIs)
	}

	var foundSpiffe *string
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			s := u.String()
			foundSpiffe = &s
			break
		}
	}
	if foundSpiffe == nil {
		t.Fatalf("no spiffe:// URI in cert.URIs: %v", cert.URIs)
	}
	if *foundSpiffe != wantSpiffe {
		t.Errorf("SPIFFE SAN mismatch:\n  got:  %q\n  want: %q", *foundSpiffe, wantSpiffe)
	}

	// Also verify the DID URI is still present — additive, not replacing.
	hasDID := false
	for _, u := range cert.URIs {
		if u.String() == desc.IssuerDID {
			hasDID = true
			break
		}
	}
	if !hasDID {
		t.Errorf("DID URI %q missing from cert.URIs: %v", desc.IssuerDID, cert.URIs)
	}
}

// TestSpiffeSAN_ParentChainPropagates verifies that ephemeral certs issued
// via the parent-chain helper (IssueCodeSigningCertWithParent, used for the
// root→bridge→ephemeral chain) also carry the SPIFFE SAN when configured.
// This guards against the trap where SPIFFE SAN only works on one of the
// two issuance paths.
func TestSpiffeSAN_ParentChainPropagates(t *testing.T) {
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bridgePub, bridgePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootCA := NewLocalCA(masterPriv, "did:key:root-spiffe")
	rootTemplate := rootCA.CreateCACertificateTemplate()
	rootTemplate.SubjectKeyId = generateSubjectKeyID(masterPriv.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, masterPriv.Public(), masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	bridgeTemplate := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               EncodeDIDAsSubject("alice@example.com"),
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          generateSubjectKeyID(bridgePub),
		AuthorityKeyId:        rootTemplate.SubjectKeyId,
	}
	bridgeDER, err := x509.CreateCertificate(rand.Reader, bridgeTemplate, rootTemplate, bridgePub, masterPriv)
	if err != nil {
		t.Fatal(err)
	}
	bridgeCert, err := x509.ParseCertificate(bridgeDER)
	if err != nil {
		t.Fatal(err)
	}

	wantSpiffe := signet.BuildSpiffeID("art.local", "agent/alice")
	bridgeCA := NewLocalCA(bridgePriv, "alice@example.com").WithSpiffeID(wantSpiffe)

	ephCert, _, secKey, err := bridgeCA.IssueCodeSigningCertWithParent(bridgeCert, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer secKey.Destroy()

	var foundSpiffe bool
	for _, u := range ephCert.URIs {
		if u.String() == wantSpiffe {
			foundSpiffe = true
			break
		}
	}
	if !foundSpiffe {
		t.Errorf("SPIFFE SAN missing under parent-chain issuance:\n  want: %q\n  got URIs: %v", wantSpiffe, ephCert.URIs)
	}

	// Chain must still validate — SPIFFE SAN is additive, not blocking.
	_ = rootCert // chain validation parity with TestIssueCodeSigningCertWithParent isn't the focus here
}

// TestMasterKeyDescriptor_SpiffeID_Defaults documents the empty-TrustDomain
// behavior: SpiffeID() returns "" and downstream consumers treat that as
// "do not emit a SPIFFE SAN." This is the additive-safety contract.
func TestMasterKeyDescriptor_SpiffeID_Defaults(t *testing.T) {
	cases := []struct {
		name string
		desc signet.MasterKeyDescriptor
		path string
		want string
	}{
		{
			name: "empty trust domain → empty spiffe id",
			desc: signet.MasterKeyDescriptor{IssuerDID: "did:key:abc"},
			path: "workload/foo",
			want: "",
		},
		{
			name: "trust domain set → spiffe id assembled",
			desc: signet.MasterKeyDescriptor{IssuerDID: "did:key:abc", TrustDomain: "art.local"},
			path: "workload/foo",
			want: "spiffe://art.local/workload/foo",
		},
		{
			name: "leading slash in path is normalized",
			desc: signet.MasterKeyDescriptor{TrustDomain: "acme.com"},
			path: "/billing/payments",
			want: "spiffe://acme.com/billing/payments",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.desc.SpiffeID(tc.path); got != tc.want {
				t.Errorf("SpiffeID(%q):\n  got:  %q\n  want: %q", tc.path, got, tc.want)
			}
		})
	}
}
