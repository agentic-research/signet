package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// signet-790ca1 — the shared OID arc, and what this verifier reports when the
// cert came from notme rather than from signet's own authority.
//
// notme, signet and ley-line-open all allocate under the IANA
// example/private-experiment arc 1.3.6.1.4.1.99999 with no registry between
// them, and the meanings disagree at .1.5 and .1.6:
//
//	OID    signet (here)      notme                        ley-line-open
//	.1.1   subject            subject                      --
//	.1.2   issuance time      issuance time                --
//	.1.3   capabilities       scopes (SEQ OF UTF8String)   --
//	.1.4   --                 epoch (INTEGER)              epoch (INTEGER)
//	.1.5   agent name         authMethod (UTF8String)      interlace-peer
//	.1.6   scope              peer binding (32 RAW bytes)  interlace-scope
//	.1.7   --                 -- (do not reuse)            confinementDigest
//	.1.8   --                 principal kind               --
//	.1.9   --                 task scope                   --
//
// Unlike LLO's collision -- which sat behind an earlier RFC 5280 rejection for
// an unknown critical extension and so never fired -- nothing shields this
// one. verifyCert reads the extensions BEFORE it verifies the chain, and Go's
// x509 handles notme's critical BasicConstraints natively, so the misread
// happens on every notme certificate regardless of whether the chain checks
// out.
//
// Every notme cert pair carries both extensions: cert-authority.ts:541-542
// writes them into `sharedExtensions`, which /cert/gha (the CI path),
// /cert/passkey and the issuing-CA and task-cert paths all build on.
func notmeStyleCertFiles(t *testing.T, authMethod string) (certPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"notme"}},
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

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	// notme writes DER UTF8String (tag 0x0c) via derUtf8String(), not Go's
	// default PrintableString -- so "utf8" params here, or the fixture would
	// exercise a shape production never emits.
	utf8DER := func(s string) []byte {
		b, err := asn1.MarshalWithParams(s, "utf8")
		if err != nil {
			t.Fatalf("marshal utf8 %q: %v", s, err)
		}
		return b
	}

	subject := "repo:agentic-research/notme:ref:refs/heads/main"

	// cert-authority.ts:542 -- raw SHA-256 bytes, no DER wrapper.
	binding := sha256.Sum256([]byte("p256-spki||ed25519-spki"))

	extensions := []pkix.Extension{
		{Id: asn1.ObjectIdentifier(sigid.OIDSubject), Value: utf8DER(subject)},
		{Id: asn1.ObjectIdentifier(sigid.OIDIssuanceTime), Value: utf8DER(time.Now().UTC().Format(time.RFC3339))},
		// .1.5 -- notme's authMethod. signet reads this slot as the agent name.
		{Id: asn1.ObjectIdentifier(sigid.OIDAgentName), Value: utf8DER(authMethod)},
		// .1.6 -- notme's peer binding. signet reads this slot as the scope.
		{Id: asn1.ObjectIdentifier(sigid.OIDScope), Value: binding[:]},
		// .1.8 -- principal kind. notme emits it on EVERY mint path and no
		// other allocation under this arc uses it, which is what makes it
		// usable as a profile discriminator.
		{Id: asn1.ObjectIdentifier(sigid.OIDPrincipalKind), Value: utf8DER("workload")},
	}

	now := time.Now()
	clientTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject, Organization: []string{"notme"}},
		NotBefore:             now,
		NotAfter:              now.Add(5 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
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

// A notme certificate is not an agent certificate. Reporting one as an agent
// named "gha-oidc" invents a fact about the identity, which is worse than
// reporting nothing: an operator reading `signet verify` output, or any caller
// branching on result.Agent, is told a workload identity is a named agent.
func TestVerifyCert_NotmeProfile_DoesNotInventAnAgent(t *testing.T) {
	for _, authMethod := range []string{"gha-oidc", "passkey", "oidc:github", "invite"} {
		t.Run(authMethod, func(t *testing.T) {
			certPath, caPath := notmeStyleCertFiles(t, authMethod)
			result, err := verifyCert(certPath, caPath)
			if err != nil {
				t.Fatalf("verifyCert: %v", err)
			}

			if result.Agent != "" {
				t.Errorf("Agent = %q, want empty: .1.5 on a notme certificate is "+
					"the authMethod, not an agent name", result.Agent)
			}
			if result.Scope != "" {
				t.Errorf("Scope = %q (%d bytes), want empty: .1.6 on a notme "+
					"certificate is a 32-byte peer binding, not a scope",
					result.Scope, len(result.Scope))
			}
			// The subject still reads correctly -- .1.1 is the one slot all
			// three allocations agree on, so the fix must not throw it away.
			if result.Owner != "repo:agentic-research/notme:ref:refs/heads/main" {
				t.Errorf("Owner = %q, want the .1.1 subject", result.Owner)
			}
		})
	}
}

// The discriminator must not cost signet's own authority anything: a cert from
// cmd/signet/authority_identity.go carries .1.5/.1.6 and NO .1.8, and must
// still report its agent and scope.
func TestVerifyCert_SignetOwnAgentCert_StillReportsAgentAndScope(t *testing.T) {
	certPath, caPath := createTestAgentCertFiles(t,
		"james@example.com", "github-12345",
		"dev-agent", "repo:signet",
		24*time.Hour)

	result, err := verifyCert(certPath, caPath)
	if err != nil {
		t.Fatalf("verifyCert: %v", err)
	}
	if result.Agent != "dev-agent" {
		t.Errorf("Agent = %q, want %q", result.Agent, "dev-agent")
	}
	if result.Scope != "repo:signet" {
		t.Errorf("Scope = %q, want %q", result.Scope, "repo:signet")
	}
}
