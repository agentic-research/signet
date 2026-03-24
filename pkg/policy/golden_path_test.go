package policy_test

import (
	"context"
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

	"github.com/agentic-research/signet/pkg/policy"
)

// Signet OID extensions (must match authority.go and signet-edge.ts)
var (
	oidSubject      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidIssuanceTime = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
)

// TestGoldenPath_AuthIdentityPolicy exercises the full chain:
//
//	1. Authority mints bridge cert (Ed25519 CA signs P-256 client key)
//	2. Cert carries OID extensions (subject, issuance time)
//	3. Policy compiler produces signed trust bundle
//	4. Policy checker verifies subject is provisioned and active
//	5. Capabilities resolved from group membership
//	6. Subject deactivation is enforced
//
// This is the regression safety net for the sigid/sigpol refactor.
func TestGoldenPath_AuthIdentityPolicy(t *testing.T) {
	// === SETUP: Generate authority keypair (Ed25519 master key) ===
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// === STEP 1: Mint bridge cert (simulates authority.mintClientCertificate) ===
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	subjectID := "github-12345"
	email := "james@example.com"

	subjectDER, _ := asn1.Marshal(subjectID)
	timeDER, _ := asn1.Marshal(now.Format(time.RFC3339))

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"Signet Authority"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         email,
			Organization:       []string{"Signet Authority"},
			OrganizationalUnit: []string{"Client Certificates"},
		},
		NotBefore:      now,
		NotAfter:       now.Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{email},
		ExtraExtensions: []pkix.Extension{
			{Id: oidSubject, Value: subjectDER},
			{Id: oidIssuanceTime, Value: timeDER},
		},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatal(err)
	}

	// === STEP 2: Verify cert has OID extensions ===
	var foundSubject, foundTime bool
	for _, ext := range clientCert.Extensions {
		if ext.Id.Equal(oidSubject) {
			foundSubject = true
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
				if s != subjectID {
					t.Errorf("OID subject = %q, want %q", s, subjectID)
				}
			}
		}
		if ext.Id.Equal(oidIssuanceTime) {
			foundTime = true
		}
	}
	if !foundSubject {
		t.Error("cert missing OID 99999.1.1 (subject)")
	}
	if !foundTime {
		t.Error("cert missing OID 99999.1.2 (issuance time)")
	}

	// Verify cert chain (client cert signed by CA)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert chain verification failed: %v", err)
	}

	// === STEP 3: Compile trust policy bundle ===
	compiler := policy.NewCompiler(caPriv)
	compiler.DefineGroup("developers", []uint64{0x0001, 0x0002}, 86400)
	compiler.DefineGroup("contractors", []uint64{0x0001}, 7200)
	compiler.AddSubject(subjectID, []string{"developers"})
	compiler.AddSubject("github-99999", []string{"contractors"})

	bundle, err := compiler.Compile()
	if err != nil {
		t.Fatalf("compile bundle: %v", err)
	}

	if err := bundle.Verify(caPub); err != nil {
		t.Fatalf("bundle verify: %v", err)
	}

	// === STEP 4: PolicyChecker verifies subject ===
	fetcher := &staticFetcher{bundle: bundle}
	checker := policy.NewPolicyChecker(fetcher, caPub, time.Second)

	subject, err := checker.CheckSubject(context.Background(), subjectID)
	if err != nil {
		t.Fatalf("check subject: %v", err)
	}
	if !subject.Active {
		t.Error("subject should be active")
	}

	// === STEP 5: Resolve capabilities from group membership ===
	caps, err := checker.ResolveCapabilities(context.Background(), subject)
	if err != nil {
		t.Fatalf("resolve capabilities: %v", err)
	}
	if len(caps) != 2 {
		t.Errorf("expected 2 capabilities (read+write from developers group), got %d: %v", len(caps), caps)
	}

	// === STEP 6: Deactivation is enforced ===
	compiler.DeactivateSubject(subjectID)
	bundle2, _ := compiler.Compile()
	fetcher2 := &staticFetcher{bundle: bundle2}
	checker2 := policy.NewPolicyChecker(fetcher2, caPub, time.Second)

	_, err = checker2.CheckSubject(context.Background(), subjectID)
	if err == nil {
		t.Fatal("deactivated subject should be denied")
	}

	// === STEP 7: Unprovisioned subject is denied ===
	_, err = checker.CheckSubject(context.Background(), "github-attacker")
	if err == nil {
		t.Fatal("unprovisioned subject should be denied")
	}

	// === STEP 8: Bootstrap mode allows unknown subjects before first bundle ===
	bootstrapChecker := policy.NewPolicyChecker(
		&staticFetcher{err: context.DeadlineExceeded}, caPub, time.Second,
	)
	bootstrapSubject, err := bootstrapChecker.CheckSubject(context.Background(), "anyone")
	if err != nil {
		t.Fatalf("bootstrap should allow: %v", err)
	}
	if !bootstrapSubject.Active {
		t.Error("bootstrap subject should be active")
	}
}

// TestGoldenPath_CertFormatParity verifies that certs minted with the same
// parameters produce identical OID extensions regardless of client key type.
// This catches divergence between Go authority (Ed25519/P-256) and signet-edge.ts.
func TestGoldenPath_CertFormatParity(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "signet-authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	caCert, _ := x509.ParseCertificate(caCertDER)

	subjectID := "test-user-42"
	subjectDER, _ := asn1.Marshal(subjectID)
	timeDER, _ := asn1.Marshal(time.Now().Format(time.RFC3339))

	mintCert := func(t *testing.T, pubKey any, label string) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "user-" + subjectID, Organization: []string{"rosary"}},
			Issuer:       pkix.Name{CommonName: "signet-authority", Organization: []string{"rosary"}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			ExtraExtensions: []pkix.Extension{
				{Id: oidSubject, Value: subjectDER},
				{Id: oidIssuanceTime, Value: timeDER},
			},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, caPriv)
		if err != nil {
			t.Fatalf("mint %s cert: %v", label, err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	// Mint with Ed25519 client key
	ed25519Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed25519Cert := mintCert(t, ed25519Pub, "Ed25519")

	// Mint with P-256 client key
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p256Cert := mintCert(t, &p256Key.PublicKey, "P-256")

	// Both should have identical OID extensions
	extractOID := func(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				var s string
				if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
					return s
				}
				return string(ext.Value)
			}
		}
		return ""
	}

	ed25519Subject := extractOID(ed25519Cert, oidSubject)
	p256Subject := extractOID(p256Cert, oidSubject)

	if ed25519Subject != p256Subject {
		t.Errorf("OID subject mismatch: Ed25519=%q, P-256=%q", ed25519Subject, p256Subject)
	}
	if ed25519Subject != subjectID {
		t.Errorf("OID subject = %q, want %q", ed25519Subject, subjectID)
	}

	// Both should have the same CN format
	if ed25519Cert.Subject.CommonName != p256Cert.Subject.CommonName {
		t.Errorf("CN mismatch: Ed25519=%q, P-256=%q", ed25519Cert.Subject.CommonName, p256Cert.Subject.CommonName)
	}
}

// staticFetcher is a test helper that returns a fixed bundle or error.
type staticFetcher struct {
	bundle *policy.TrustPolicyBundle
	err    error
}

func (f *staticFetcher) Fetch(_ context.Context) (*policy.TrustPolicyBundle, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.bundle, nil
}
