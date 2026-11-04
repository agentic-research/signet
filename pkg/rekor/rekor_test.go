package rekor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/rekor/rekortest"
)

// The v0.3.1 release's linux-amd64 bundle, as published: logged in the
// public-good Rekor at 2026-10-28T23:39:48Z.
const (
	releaseBundle         = "testdata/signet-v0.3.1-linux-amd64.sigstore.json"
	releaseIntegratedTime = 1793230788
	releaseLogIndex       = 3552326250
)

func readRelease(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(releaseBundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bundleLeaf returns the certificate inside a bundle, so a test can hand
// VerifyBundle the cert it should match.
func bundleLeaf(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	var b struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificate"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// edit applies f to the bundle's decoded JSON and re-encodes it.
func edit(t *testing.T, raw []byte, f func(b map[string]any)) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	f(b)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tlog(b map[string]any) map[string]any {
	return b["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
}

func TestVerifyBundle_ReleaseV031(t *testing.T) {
	raw := readRelease(t)
	res, err := VerifyBundle(raw, bundleLeaf(t, raw), Options{})
	if err != nil {
		t.Fatalf("published v0.3.1 bundle refused: %v", err)
	}
	if res.IntegratedTime.Unix() != releaseIntegratedTime {
		t.Fatalf("integrated time %d, want %d", res.IntegratedTime.Unix(), releaseIntegratedTime)
	}
	if res.LogIndex != releaseLogIndex {
		t.Fatalf("log index %d, want %d", res.LogIndex, releaseLogIndex)
	}
	if res.ArtifactChecked {
		t.Fatal("no artifact was given, yet it reports one checked")
	}
}

func TestVerifyBundle_ReleaseTamperRefused(t *testing.T) {
	raw := readRelease(t)
	leaf := bundleLeaf(t, raw)
	cases := map[string]func(b map[string]any){
		// The time is what the caller relies on: only the SET covers it.
		"integrated time moved": func(b map[string]any) { tlog(b)["integratedTime"] = "1793230000" },
		"log index changed":     func(b map[string]any) { tlog(b)["logIndex"] = "3552326251" },
		"SET corrupted": func(b map[string]any) {
			tlog(b)["inclusionPromise"] = map[string]any{"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("nope"))}
		},
		"SET missing": func(b map[string]any) { delete(tlog(b), "inclusionPromise") },
		"proof hash changed": func(b map[string]any) {
			p := tlog(b)["inclusionProof"].(map[string]any)
			h := p["hashes"].([]any)
			h[0] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
		"proof missing": func(b map[string]any) { delete(tlog(b), "inclusionProof") },
		"checkpoint root changed": func(b map[string]any) {
			p := tlog(b)["inclusionProof"].(map[string]any)
			cp := p["checkpoint"].(map[string]any)
			env := cp["envelope"].(string)
			cp["envelope"] = strings.Replace(env, "\n3430422204\n", "\n3430422205\n", 1)
		},
		"body signature swapped": func(b map[string]any) {
			ms := b["messageSignature"].(map[string]any)
			ms["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"no tlog entries": func(b map[string]any) {
			b["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{}
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyBundle(edit(t, raw, f), leaf, Options{}); err == nil {
				t.Fatal("tampered bundle verified")
			}
		})
	}
}

func TestVerifyBundle_ReleaseOtherLeafRefused(t *testing.T) {
	raw := readRelease(t)
	other, _ := newLeaf(t, time.Unix(releaseIntegratedTime, 0), false)
	if _, err := VerifyBundle(raw, other, Options{}); !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("bundle verified for a different certificate: %v", err)
	}
}

func newLeaf(t *testing.T, at time.Time, ecdsaKey bool) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	var (
		pub  crypto.PublicKey
		priv crypto.Signer
	)
	if ecdsaKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, priv = &k.PublicKey, k
	} else {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		pub, priv = p, k
	}
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    at.Add(-time.Minute),
		NotAfter:     at.Add(4 * time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, priv
}

func fakeBundle(t *testing.T, log *rekortest.Log, leaf *x509.Certificate, signer crypto.Signer, artifact []byte, at time.Time) []byte {
	t.Helper()
	b, err := log.Bundle(rekortest.Entry{Leaf: leaf.Raw, Signer: signer, Artifact: artifact, IntegratedTime: at, LogIndex: 99})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyBundle_FakeLog(t *testing.T) {
	log, err := rekortest.NewLog()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1767225000, 0)
	opts := Options{Logs: []crypto.PublicKey{log.PublicKey()}}
	for _, ec := range []bool{false, true} {
		leaf, signer := newLeaf(t, at, ec)
		raw := fakeBundle(t, log, leaf, signer, []byte("artifact"), at)

		res, err := VerifyBundle(raw, leaf, opts)
		if err != nil {
			t.Fatalf("ecdsa=%v: %v", ec, err)
		}
		if !res.IntegratedTime.Equal(at) || res.LogIndex != 99 {
			t.Fatalf("ecdsa=%v: got %v / %d", ec, res.IntegratedTime, res.LogIndex)
		}

		withArt := opts
		withArt.Artifact = bytes.NewReader([]byte("artifact"))
		res, err = VerifyBundle(raw, leaf, withArt)
		if err != nil || !res.ArtifactChecked {
			t.Fatalf("ecdsa=%v: artifact check: %v (checked %v)", ec, err, res != nil && res.ArtifactChecked)
		}
		wrongArt := opts
		wrongArt.Artifact = bytes.NewReader([]byte("another artifact"))
		if _, err := VerifyBundle(raw, leaf, wrongArt); !errors.Is(err, ErrArtifactMismatch) {
			t.Fatalf("ecdsa=%v: wrong artifact: %v", ec, err)
		}
	}
}

func TestVerifyBundle_UntrustedLogRefused(t *testing.T) {
	log, _ := rekortest.NewLog()
	at := time.Unix(1767225000, 0)
	leaf, signer := newLeaf(t, at, false)
	raw := fakeBundle(t, log, leaf, signer, []byte("a"), at)
	// Default options trust only the public-good log.
	if _, err := VerifyBundle(raw, leaf, Options{}); !errors.Is(err, ErrNoTrustedEntry) {
		t.Fatalf("entry from an unknown log accepted: %v", err)
	}
}

// A log key the caller trusts must also be the one that signed: a bundle
// naming the trusted log's id but signed by another key is refused.
func TestVerifyBundle_ForgedSETRefused(t *testing.T) {
	trusted, _ := rekortest.NewLog()
	forger, _ := rekortest.NewLog()
	at := time.Unix(1767225000, 0)
	leaf, signer := newLeaf(t, at, false)
	raw := fakeBundle(t, forger, leaf, signer, []byte("a"), at)
	// Relabel the entry with the trusted log's id.
	trustedRaw := fakeBundle(t, trusted, leaf, signer, []byte("a"), at)
	var tb map[string]any
	_ = json.Unmarshal(trustedRaw, &tb)
	raw = edit(t, raw, func(b map[string]any) { tlog(b)["logId"] = tlog(tb)["logId"] })
	if _, err := VerifyBundle(raw, leaf, Options{Logs: []crypto.PublicKey{trusted.PublicKey()}}); err == nil {
		t.Fatal("SET signed by another key verified")
	}
}

func TestVerifyBundle_NoEntryIsNamed(t *testing.T) {
	raw := edit(t, readRelease(t), func(b map[string]any) {
		delete(b["verificationMaterial"].(map[string]any), "tlogEntries")
	})
	if _, err := VerifyBundle(raw, bundleLeaf(t, readRelease(t)), Options{}); !errors.Is(err, ErrNoTlogEntry) {
		t.Fatalf("got %v, want ErrNoTlogEntry", err)
	}
}

func TestRootFromInclusionProof(t *testing.T) {
	// Three leaves: root = H(H(l0, l1), l2). Independent of the code under
	// test: built from hashChildren/hashLeaf definitions in RFC 6962 §2.1.
	l := [][]byte{hashLeaf([]byte("a")), hashLeaf([]byte("b")), hashLeaf([]byte("c"))}
	n01 := hashChildren(l[0], l[1])
	root := hashChildren(n01, l[2])
	cases := []struct {
		index uint64
		proof [][]byte
	}{
		{0, [][]byte{l[1], l[2]}},
		{1, [][]byte{l[0], l[2]}},
		{2, [][]byte{n01}},
	}
	for _, c := range cases {
		got, err := rootFromInclusionProof(c.index, 3, l[c.index], c.proof)
		if err != nil || !bytes.Equal(got, root) {
			t.Fatalf("index %d: %x %v", c.index, got, err)
		}
	}
	if _, err := rootFromInclusionProof(3, 3, l[0], nil); err == nil {
		t.Fatal("index beyond the tree accepted")
	}
	if _, err := rootFromInclusionProof(2, 3, l[2], [][]byte{n01, n01}); err == nil {
		t.Fatal("proof of the wrong length accepted")
	}
}

// The log vouches for the time; the signature itself is still checked, so
// an entry whose signature does not verify under the certificate is refused.
func TestVerifyBundle_BadSignatureRefused(t *testing.T) {
	log, _ := rekortest.NewLog()
	at := time.Unix(1767225000, 0)
	for _, ec := range []bool{false, true} {
		leaf, signer := newLeaf(t, at, ec)
		raw, err := log.Bundle(rekortest.Entry{Leaf: leaf.Raw, Signer: signer, Artifact: []byte("a"), IntegratedTime: at, BadSignature: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBundle(raw, leaf, Options{Logs: []crypto.PublicKey{log.PublicKey()}}); err == nil {
			t.Fatalf("ecdsa=%v: bad signature verified", ec)
		}
	}
}

// The log entry must name the same certificate the bundle carries.
func TestVerifyBundle_EntryForOtherCertRefused(t *testing.T) {
	log, _ := rekortest.NewLog()
	at := time.Unix(1767225000, 0)
	leaf, signer := newLeaf(t, at, false)
	other, _ := newLeaf(t, at, false)
	raw, err := log.Bundle(rekortest.Entry{Leaf: leaf.Raw, BodyLeaf: other.Raw, Signer: signer, Artifact: []byte("a"), IntegratedTime: at})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(raw, leaf, Options{Logs: []crypto.PublicKey{log.PublicKey()}}); !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("entry naming another certificate: %v", err)
	}
}
