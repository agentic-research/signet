package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/revocation"
	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/agentic-research/signet/pkg/sigid"
)

// signet-5b1590: `signet verify` reported "Certificate valid" without
// asking the authority whether the cert had been revoked. notme revokes by
// bumping its CA epoch (POST /admin/revoke-epoch); every cert carries the
// epoch it was minted under (OID .1.4, DER INTEGER) and the authority
// publishes its current epoch in a CA bundle signed by the root key. These
// tests drive the command's own code path against a real root -> tier ->
// task chain and a bundle server signed by that root.

const testBundleKID = "3b8b237e"

// noEpoch omits the epoch extension from a cert.
const noEpoch = -1

type epochChain struct {
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	rootPath  string
	chainPath string
}

func epochExt(t *testing.T, epoch int64) pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(epoch)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}, Value: v}
}

// newEpochChain builds root -> tier -> task, notme-shaped, with the given
// CA epoch on the tier and on the task leaf.
func newEpochChain(t *testing.T, tierEpoch, leafEpoch int64) epochChain {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()

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

	tierURI, _ := url.Parse(tierIdentity)
	tierPub, tierPriv, _ := ed25519.GenerateKey(rand.Reader)
	tierTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "demo"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{tierURI},
	}
	if tierEpoch != noEpoch {
		tierTmpl.ExtraExtensions = []pkix.Extension{epochExt(t, tierEpoch)}
	}
	tierDER, err := x509.CreateCertificate(rand.Reader, tierTmpl, root, tierPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	tier, _ := x509.ParseCertificate(tierDER)

	taskURI, _ := url.Parse(tierIdentity + "/" + taskID)
	taskPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subj, _ := asn1.MarshalWithParams(taskID, "utf8")
	kind, _ := asn1.MarshalWithParams("agent", "utf8")
	exts := []pkix.Extension{
		{Id: asn1.ObjectIdentifier(sigid.OIDSubject), Value: subj},
		{Id: asn1.ObjectIdentifier(sigid.OIDPrincipalKind), Value: kind},
	}
	if leafEpoch != noEpoch {
		exts = append(exts, epochExt(t, leafEpoch))
	}
	taskTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: taskID},
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(5 * time.Minute),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:            []*url.URL{taskURI},
		ExtraExtensions: exts,
	}
	taskDER, err := x509.CreateCertificate(rand.Reader, taskTmpl, tier, taskPub, tierPriv)
	if err != nil {
		t.Fatal(err)
	}

	return epochChain{
		rootPub:   rootPub,
		rootPriv:  rootPriv,
		rootPath:  writeFile(t, dir, "root.pem", pemCert(rootDER)),
		chainPath: writeFile(t, dir, "chain.pem", pemCert(taskDER), pemCert(tierDER)),
	}
}

// signedBundle returns a bundle for the chain's root at the given epoch,
// seqno and issue time, signed by signer over the canonical CBOR bytes.
func signedBundle(t *testing.T, c epochChain, signer ed25519.PrivateKey, epoch, seqno uint64, issuedAt time.Time) *types.CABundle {
	t.Helper()
	b := &types.CABundle{
		Epoch:    epoch,
		Seqno:    seqno,
		Keys:     map[string][]byte{testBundleKID: []byte(c.rootPub)},
		KeyID:    testBundleKID,
		IssuedAt: issuedAt.Unix(),
	}
	canonical, err := revocation.BundleCanonical(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(signer, canonical)
	return b
}

// bundleServer serves whatever bundle is current at /internal/ca-bundle.
type bundleServer struct {
	*httptest.Server
	mu     sync.Mutex
	bundle *types.CABundle
}

func newBundleServer(t *testing.T, b *types.CABundle) *bundleServer {
	t.Helper()
	s := &bundleServer{bundle: b}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/ca-bundle" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.bundle)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *bundleServer) set(b *types.CABundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = b
}

func runVerifyForTest(t *testing.T, c epochChain, opts verifyOptions) (string, error) {
	t.Helper()
	opts.caPath = c.rootPath
	if opts.stateDir == "" {
		opts.stateDir = t.TempDir()
	}
	var out bytes.Buffer
	err := verifyAndReport(context.Background(), &out, c.chainPath, opts)
	return out.String(), err
}

func onlineOpts(srv *bundleServer) verifyOptions {
	return verifyOptions{authority: srv.URL, client: srv.Client()}
}

func wantRefused(t *testing.T, out string, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("verify accepted the certificate; output:\n%s", out)
	}
	if strings.Contains(out, "Certificate valid") {
		t.Fatalf("output claims validity despite the error %v:\n%s", err, out)
	}
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not mention %q", err, f)
		}
	}
}

func TestVerifyRevocation_CurrentEpochVerifies(t *testing.T) {
	c := newEpochChain(t, 3, 3)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now().Add(-30*time.Second)))

	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	if err != nil {
		t.Fatalf("current-epoch cert refused: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Certificate valid") {
		t.Fatalf("missing validity line:\n%s", out)
	}
	if !strings.Contains(out, "Revocation: checked (epoch 3, bundle age ") {
		t.Fatalf("output does not report the revocation check:\n%s", out)
	}
	if strings.Contains(out, "NOT checked") {
		t.Fatalf("online check says NOT checked:\n%s", out)
	}
}

func TestVerifyRevocation_OldEpochRefused(t *testing.T) {
	t.Run("leaf and tier from an old epoch", func(t *testing.T) {
		c := newEpochChain(t, 2, 2)
		srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now()))
		out, err := runVerifyForTest(t, c, onlineOpts(srv))
		wantRefused(t, out, err, "epoch 2", "epoch 3", "revoked")
	})
	t.Run("current leaf under an old-epoch tier", func(t *testing.T) {
		c := newEpochChain(t, 2, 3)
		srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now()))
		out, err := runVerifyForTest(t, c, onlineOpts(srv))
		wantRefused(t, out, err, "epoch 2", "revoked")
	})
}

func TestVerifyRevocation_FutureEpochRefused(t *testing.T) {
	// notme's own verifier is strict (!==): a cert from an epoch the
	// authority has not reached is not a rotation case.
	c := newEpochChain(t, 4, 4)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now()))
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "epoch 4", "ahead")
}

func TestVerifyRevocation_MissingEpochRefused(t *testing.T) {
	c := newEpochChain(t, 3, noEpoch)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now()))
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "no epoch")
}

func TestVerifyRevocation_BadBundleSignatureRefused(t *testing.T) {
	c := newEpochChain(t, 3, 3)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	srv := newBundleServer(t, signedBundle(t, c, attacker, 3, 10, time.Now()))
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "signature")
}

func TestVerifyRevocation_TamperedBundleRefused(t *testing.T) {
	// Signed at epoch 1, served claiming epoch 3... or the reverse: an
	// attacker lowering the epoch to un-revoke old certs.
	c := newEpochChain(t, 2, 2)
	b := signedBundle(t, c, c.rootPriv, 3, 10, time.Now())
	b.Epoch = 2
	srv := newBundleServer(t, b)
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "signature")
}

func TestVerifyRevocation_StaleBundleRefused(t *testing.T) {
	c := newEpochChain(t, 3, 3)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now().Add(-2*time.Hour)))
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "too old")
}

func TestVerifyRevocation_BundleWithoutIssuedAtRefused(t *testing.T) {
	// The checker skips the age check when issuedAt is 0, for older
	// producers. Here freshness is the point, so it is required.
	c := newEpochChain(t, 3, 3)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Unix(0, 0)))
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "issuedAt")
}

func TestVerifyRevocation_RollbackRefused(t *testing.T) {
	c := newEpochChain(t, 3, 3)
	srv := newBundleServer(t, signedBundle(t, c, c.rootPriv, 3, 10, time.Now()))
	opts := onlineOpts(srv)
	opts.stateDir = t.TempDir() // shared across both runs

	if out, err := runVerifyForTest(t, c, opts); err != nil {
		t.Fatalf("first run refused: %v\n%s", err, out)
	}
	srv.set(signedBundle(t, c, c.rootPriv, 3, 9, time.Now()))
	out, err := runVerifyForTest(t, c, opts)
	wantRefused(t, out, err, "rollback")
}

func TestVerifyRevocation_AnchorNotInBundleRefused(t *testing.T) {
	// The bundle is validly signed by the root but no longer lists the
	// root's key: the authority has rotated away from it.
	c := newEpochChain(t, 3, 3)
	b := signedBundle(t, c, c.rootPriv, 3, 10, time.Now())
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	b.Keys = map[string][]byte{"ffffffff": []byte(other)}
	b.KeyID = "ffffffff"
	canonical, err := revocation.BundleCanonical(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(c.rootPriv, canonical)
	srv := newBundleServer(t, b)
	out, err := runVerifyForTest(t, c, onlineOpts(srv))
	wantRefused(t, out, err, "not in the authority's bundle")
}

func TestVerifyRevocation_UnreachableAuthorityFailsClosed(t *testing.T) {
	c := newEpochChain(t, 3, 3)
	srv := newBundleServer(t, nil)
	srv.Close() // nothing listens at this address any more
	opts := onlineOpts(srv)
	opts.client.Timeout = 2 * time.Second
	out, err := runVerifyForTest(t, c, opts)
	wantRefused(t, out, err, "fetch")
}

func TestVerifyRevocation_OfflineSaysNotChecked(t *testing.T) {
	c := newEpochChain(t, 2, 2) // an old epoch: --offline cannot see it
	out, err := runVerifyForTest(t, c, verifyOptions{
		authority: "https://127.0.0.1:1", // must not be contacted
		offline:   true,
	})
	if err != nil {
		t.Fatalf("--offline refused a chain-valid cert: %v\n%s", err, out)
	}
	if !strings.Contains(out, "revocation NOT checked") {
		t.Fatalf("--offline output does not say revocation NOT checked:\n%s", out)
	}
	if strings.Contains(out, "Revocation: checked") {
		t.Fatalf("--offline output claims a check:\n%s", out)
	}
}

func TestVerifyRevocation_ChainFailureSkipsFetch(t *testing.T) {
	// A cert that does not chain is invalid before any network call.
	c := newEpochChain(t, 3, 3)
	other := newEpochChain(t, 3, 3)
	c.rootPath = other.rootPath
	out, err := runVerifyForTest(t, c, verifyOptions{authority: "https://127.0.0.1:1", client: http.DefaultClient})
	wantRefused(t, out, err, "unknown authority")
}

func TestResolveRevocationAuthority(t *testing.T) {
	u, _ := url.Parse("wimse://notme.bot/principal/alice/task")
	leaf := &x509.Certificate{URIs: []*url.URL{u}}

	cases := []struct {
		name, flag, want string
		leaf             *x509.Certificate
		wantErr          bool
	}{
		{"derived from the wimse trust domain", "", "https://auth.notme.bot", leaf, false},
		{"flag wins", "https://ca.example.com/", "https://ca.example.com", leaf, false},
		{"no wimse URI and no flag", "", "", &x509.Certificate{}, true},
		{"plain http is refused", "http://ca.example.com", "", leaf, true},
		{"loopback http is allowed", "http://127.0.0.1:8080", "http://127.0.0.1:8080", leaf, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRevocationAuthority(tc.flag, tc.leaf)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
