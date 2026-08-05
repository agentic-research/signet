package git

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/agentic-research/go-cms/pkg/cms"
	attestx509 "github.com/agentic-research/signet/pkg/attest/x509"
)

// CMS sign→verify round-trip against the EXACT options the production paths
// use — cms.SignOptions from signAndOutput (sign.go) and cms.VerifyOptions
// from the verify path (verify.go: CA-rooted, code-signing EKU, time
// validation skipped for historical commits).
//
// Why this exists: commit signing is this repository's headline claim, and
// until now its only coverage was the Docker integration suite, which does
// not run without a Docker daemon. That left the go-cms verifier-hardening
// bump (signet-e6a047: RFC 5652 Version/eContentType/DER-length checks) with
// no Docker-free regression guard on the path it changes. See signet-279902.

// signetCMSTestFixture builds a CA, an ephemeral code-signing leaf, and the
// trust pool a verifier would construct from the published CA bundle.
type signetCMSTestFixture struct {
	leaf     *x509.Certificate
	leafKey  ed25519.PrivateKey
	roots    *x509.CertPool
	verifyCA *x509.Certificate
}

func newSignetCMSTestFixture(t *testing.T) signetCMSTestFixture {
	t.Helper()

	_, masterKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	ca := attestx509.NewLocalCA(masterKey, "did:signet:test-authority")

	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leaf, _, err := ca.IssueEphemeralCertificate(leafPub, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue ephemeral certificate: %v", err)
	}

	// A verifier builds its trust pool from the CA bundle PEM, exactly as
	// verify.go does from the on-disk/published anchor.
	caPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatalf("CA bundle PEM: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("CA bundle PEM did not decode")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return signetCMSTestFixture{leaf: leaf, leafKey: leafPriv, roots: roots, verifyCA: caCert}
}

func (f signetCMSTestFixture) verifyOptions() cms.VerifyOptions {
	return cms.VerifyOptions{
		Roots:              f.roots,
		KeyUsages:          []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SkipTimeValidation: true,
	}
}

func TestCMSSignVerifyRoundTrip(t *testing.T) {
	f := newSignetCMSTestFixture(t)
	commitData := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nsigned commit body\n")

	signature, err := cms.SignDataWithOptions(commitData, f.leaf, f.leafKey, cms.SignOptions{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	certs, err := cms.Verify(signature, commitData, f.verifyOptions())
	if err != nil {
		t.Fatalf("verify of freshly signed data must succeed: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("verify returned no signer certificates")
	}
	if !certs[0].Equal(f.leaf) {
		t.Fatalf("verify returned a different signer certificate: %s", certs[0].Subject)
	}
}

// The verifier must reject a signature presented over different data — the
// property that makes a commit signature mean anything.
func TestCMSVerifyRejectsTamperedData(t *testing.T) {
	f := newSignetCMSTestFixture(t)
	commitData := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\noriginal body\n")

	signature, err := cms.SignDataWithOptions(commitData, f.leaf, f.leafKey, cms.SignOptions{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ntampered body!\n")
	if _, err := cms.Verify(signature, tampered, f.verifyOptions()); err == nil {
		t.Fatal("verify accepted a signature over different data")
	}
}

// A signature that chains to a DIFFERENT CA must not verify against this
// trust anchor, however well-formed it is.
func TestCMSVerifyRejectsForeignTrustRoot(t *testing.T) {
	signerFixture := newSignetCMSTestFixture(t)
	verifierFixture := newSignetCMSTestFixture(t) // independent CA

	commitData := []byte("commit signed under a foreign authority\n")
	signature, err := cms.SignDataWithOptions(commitData, signerFixture.leaf, signerFixture.leafKey, cms.SignOptions{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := cms.Verify(signature, commitData, verifierFixture.verifyOptions()); err == nil {
		t.Fatal("verify accepted a signature chaining to an untrusted CA")
	}
}

// Truncated or corrupted signature bytes must fail cleanly rather than panic
// — this is the path that meets arbitrary commit signatures from any author.
func TestCMSVerifyRejectsMalformedSignature(t *testing.T) {
	f := newSignetCMSTestFixture(t)
	commitData := []byte("commit body\n")

	signature, err := cms.SignDataWithOptions(commitData, f.leaf, f.leafKey, cms.SignOptions{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cases := map[string][]byte{
		"truncated": signature[:len(signature)/2],
		"empty":     {},
		"garbage":   []byte("not a CMS structure at all"),
		"byte-flipped": func() []byte {
			corrupted := make([]byte, len(signature))
			copy(corrupted, signature)
			corrupted[len(corrupted)/2] ^= 0xFF
			return corrupted
		}(),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cms.Verify(sig, commitData, f.verifyOptions()); err == nil {
				t.Fatalf("verify accepted a %s signature", name)
			}
		})
	}
}
