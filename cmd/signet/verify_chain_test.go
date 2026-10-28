package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/sigid"
)

// signet-53b31c: notme's delegation chain is root (pathlen 1) -> tier (Issuing
// CA, pathlen 0, held by a machine) -> task cert. Measured before the fix:
// `signet verify task/chain.pem --ca root.pem` failed with "certificate signed
// by unknown authority", because verifyCert read only the first certificate
// and passed no intermediates. openssl verify -untrusted tier.pem passes.

const (
	tierIdentity = "wimse://notme.bot/principal/alice%40example.com"
	taskID       = "rosary-056d96"
)

type notmeChain struct {
	rootPEM, tierPEM, taskPEM []byte
	otherTierPEM              []byte // same subject, different key: must not chain
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newNotmeChain(t *testing.T) notmeChain {
	t.Helper()
	now := time.Now()

	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"notme"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	mkTier := func(serial int64) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		u, _ := url.Parse(tierIdentity)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "demo"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(12 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign,
			URIs:                  []*url.URL{u},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootPriv)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return der, c, priv
	}
	tierDER, tier, tierPriv := mkTier(2)
	otherDER, _, _ := mkTier(3)

	ext := func(oid []int, v any, params string) pkix.Extension {
		b, err := asn1.MarshalWithParams(v, params)
		if err != nil {
			t.Fatal(err)
		}
		return pkix.Extension{Id: asn1.ObjectIdentifier(oid), Value: b}
	}
	taskScope, err := asn1.Marshal(struct {
		Task     string `asn1:"utf8"`
		GoalHash []byte
	}{taskID, make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	taskURI, _ := url.Parse(tierIdentity + "/" + taskID)
	taskPub, _, _ := ed25519.GenerateKey(rand.Reader)
	taskTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: taskID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{taskURI},
		ExtraExtensions: []pkix.Extension{
			ext(sigid.OIDSubject, taskID, "utf8"),
			ext(sigid.OIDPrincipalKind, "agent", "utf8"),
			{Id: asn1.ObjectIdentifier(sigid.OIDTaskScope), Value: taskScope},
		},
	}
	taskDER, err := x509.CreateCertificate(rand.Reader, taskTmpl, tier, taskPub, tierPriv)
	if err != nil {
		t.Fatal(err)
	}
	return notmeChain{
		rootPEM: pemCert(rootDER), tierPEM: pemCert(tierDER), taskPEM: pemCert(taskDER),
		otherTierPEM: pemCert(otherDER),
	}
}

func writeFile(t *testing.T, dir, name string, parts ...[]byte) string {
	t.Helper()
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, all, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyCert_NotmeTaskChain(t *testing.T) {
	c := newNotmeChain(t)
	dir := t.TempDir()
	rootPath := writeFile(t, dir, "root.pem", c.rootPEM)

	t.Run("leaf plus tier in the cert file verifies", func(t *testing.T) {
		r, err := verifyCert(writeFile(t, dir, "chain.pem", c.taskPEM, c.tierPEM), rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Valid {
			t.Fatalf("Valid = false: %s", r.Reason)
		}
	})

	t.Run("a different tier with the same subject does not", func(t *testing.T) {
		r, err := verifyCert(writeFile(t, dir, "wrong.pem", c.taskPEM, c.otherTierPEM), rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid {
			t.Fatal("verified a task cert through a tier that did not sign it")
		}
	})

	t.Run("the leaf alone cannot reach the root", func(t *testing.T) {
		r, err := verifyCert(writeFile(t, dir, "leaf.pem", c.taskPEM), rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if r.Valid {
			t.Fatal("verified a two-hop leaf with no intermediate")
		}
	})

	t.Run("reports the task as Task and the tier's principal as Sponsor", func(t *testing.T) {
		r, err := verifyCert(writeFile(t, dir, "chain2.pem", c.taskPEM, c.tierPEM), rootPath)
		if err != nil {
			t.Fatal(err)
		}
		if r.Task != taskID {
			t.Errorf("Task = %q, want %q", r.Task, taskID)
		}
		if r.Owner != tierIdentity {
			t.Errorf("Owner (Sponsor) = %q, want the tier's identity %q", r.Owner, tierIdentity)
		}
		if r.Agent != "" || r.Scope != "" {
			t.Errorf("Agent/Scope = %q/%q, want empty for a notme cert", r.Agent, r.Scope)
		}
	})
}
