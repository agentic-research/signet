package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/rekor"
	"github.com/agentic-research/signet/pkg/rekor/rekortest"
)

// signet-677e94: release certificates live five minutes, so at install time
// `signet verify` refused them as expired before ever reaching revocation.
// These tests verify "as of the signing time": T is the Rekor integrated
// time of the signature, verified; the chain is verified at T; revocation
// is judged against the authority's SIGNED epoch history (notme ADR-019
// D7). The histories are notme's golden fixtures, signed by the root whose
// Ed25519 seed is 0x00..0x1f, so the chains here are built under that root.

const (
	epochFixtures = "../../pkg/revocation/epochhistory/testdata/notme-fixtures"
	releaseDir    = "testdata/release-v0.3.1"
)

// In epochhistory-revoked: epoch 1 revoked at 02:00Z, current epoch 2,
// issued at 03:00Z. epochhistory-basic: epoch 1 current, issued 00:00Z.
var (
	fixtureRevokedAt = time.Unix(1767232800, 0).UTC()
	beforeRevocation = fixtureRevokedAt.Add(-time.Hour)       // 01:00Z
	afterRevocation  = fixtureRevokedAt.Add(30 * time.Minute) // 02:30Z
)

func fixtureRootKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

type atChain struct {
	rootPath string
	leafPath string
	leaf     *x509.Certificate
	leafKey  ed25519.PrivateKey
}

// newAtChain builds root -> leaf, notme bridge-cert shaped: a five-minute
// leaf around signedAt, carrying epoch, under the fixture root. By now the
// leaf is long expired.
func newAtChain(t *testing.T, epoch int64, signedAt time.Time) atChain {
	t.Helper()
	dir := t.TempDir()
	rootKey := fixtureRootKey()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signet-authority", Organization: []string{"notme"}},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafPub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "repo:example/project:ref:refs/tags/v1.0.0", Organization: []string{"notme"}},
		NotBefore:       signedAt.Add(-time.Minute),
		NotAfter:        signedAt.Add(4 * time.Minute),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{epochExt(t, epoch)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, leafPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return atChain{
		rootPath: writeFile(t, dir, "root.pem", pemCert(rootDER)),
		leafPath: writeFile(t, dir, "leaf.pem", pemCert(leafDER)),
		leaf:     leaf,
		leafKey:  leafKey,
	}
}

// signAt logs a signature by the chain's leaf over artifact, at signedAt,
// in log, and writes the bundle with the artifact beside it ("artifact").
func (c atChain) signAt(t *testing.T, log *rekortest.Log, artifact []byte, signedAt time.Time) string {
	t.Helper()
	b, err := log.Bundle(rekortest.Entry{Leaf: c.leaf.Raw, Signer: c.leafKey, Artifact: artifact, IntegratedTime: signedAt, LogIndex: 7})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, dir, "artifact", artifact)
	return writeFile(t, dir, "artifact.sigstore.json", b)
}

// historyServer serves an epochs.json body that a test can swap.
type historyServer struct {
	*httptest.Server
	mu   sync.Mutex
	body []byte
}

func newHistoryServer(t *testing.T, body []byte) *historyServer {
	t.Helper()
	s := &historyServer{body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/epochs.json" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *historyServer) set(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

func fixtureHistory(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(epochFixtures, name+".json")) // #nosec G304 - test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestLog(t *testing.T) *rekortest.Log {
	t.Helper()
	log, err := rekortest.NewLog()
	if err != nil {
		t.Fatal(err)
	}
	return log
}

// atOpts verifies against bundlePath and the artifact signAt wrote beside
// it, trusting log, with the history server as the authority.
func atOpts(srv *historyServer, log *rekortest.Log, bundlePath string) verifyOptions {
	return verifyOptions{
		authority:    srv.URL,
		client:       srv.Client(),
		bundlePath:   bundlePath,
		artifactPath: filepath.Join(filepath.Dir(bundlePath), "artifact"),
		rekorLogs:    trustLog(log),
	}
}

func trustLog(log *rekortest.Log) []rekor.Log {
	return []rekor.Log{{Key: log.PublicKey(), ValidFrom: time.Unix(1, 0)}}
}

// strictOpts is atOpts in strict mode, with the clock set just after the
// history fixture was issued, so it is fresh.
func strictOpts(srv *historyServer, log *rekortest.Log, bundlePath string, issuedAt time.Time) verifyOptions {
	o := atOpts(srv, log, bundlePath)
	o.strictRevocation = true
	o.clock = issuedAt.Add(time.Minute)
	return o
}

var (
	revokedIssuedAt = time.Unix(1767236400, 0).UTC() // epochhistory-revoked
	basicIssuedAt   = time.Unix(1767225600, 0).UTC() // epochhistory-basic
)

func runVerifyAt(t *testing.T, c atChain, opts verifyOptions) (string, error) {
	t.Helper()
	opts.caPath = c.rootPath
	if opts.stateDir == "" {
		opts.stateDir = t.TempDir()
	}
	var out bytes.Buffer
	err := verifyAndReport(context.Background(), &out, c.leafPath, opts)
	return out.String(), err
}

func TestVerifyAt_SignedBeforeRevocationPasses(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))

	// Without a trusted time the leaf is simply expired, and the output says
	// revocation can only be checked as of now.
	out, err := runVerifyAt(t, c, verifyOptions{authority: srv.URL, client: srv.Client()})
	if err == nil || !strings.Contains(out, "expired") {
		t.Fatalf("expired leaf accepted without a signing time: %v\n%s", err, out)
	}
	if !strings.Contains(out, "revocation can only be checked as of now") {
		t.Fatalf("expired-cert output does not say revocation can only be checked as of now:\n%s", out)
	}

	out, err = runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("artifact"), beforeRevocation)))
	if err != nil {
		t.Fatalf("signature made before the revocation refused: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Certificate valid as of its signing time",
		"Signed at: " + beforeRevocation.Format(time.RFC3339) + " (Rekor integrated time, log index 7, verified)",
		"Revocation: checked as of the signing time: epoch 1 not revoked at or before it",
		"seqno 42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("a Rekor-verified time is labelled unverified:\n%s", out)
	}
}

func TestVerifyAt_SignedAfterRevocationRefused(t *testing.T) {
	c := newAtChain(t, 1, afterRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("a"), afterRevocation)))
	wantRefused(t, out, err, "epoch_revoked", "key compromise suspected")
}

func TestVerifyAt_StrictRefusesAnyRevokedEpoch(t *testing.T) {
	for _, at := range []time.Time{beforeRevocation, afterRevocation} {
		c := newAtChain(t, 1, at)
		log := newTestLog(t)
		srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
		opts := strictOpts(srv, log, c.signAt(t, log, []byte("a"), at), revokedIssuedAt)
		out, err := runVerifyAt(t, c, opts)
		wantRefused(t, out, err, "epoch_revoked", "strict")
	}
	// Strict does not touch an epoch that was never revoked.
	c := newAtChain(t, 2, afterRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	opts := strictOpts(srv, log, c.signAt(t, log, []byte("a"), afterRevocation), revokedIssuedAt)
	if out, err := runVerifyAt(t, c, opts); err != nil {
		t.Fatalf("strict refused the current, unrevoked epoch: %v\n%s", err, out)
	}
}

func TestVerifyAt_TamperedHistoryRefused(t *testing.T) {
	c := newAtChain(t, 1, afterRevocation)
	log := newTestLog(t)
	// Moving the revocation past T is what an attacker serving the document
	// would do to make a signature by a compromised epoch verify again.
	doc := strings.Replace(string(fixtureHistory(t, "epochhistory-revoked")), `"revokedAt": 1767232800`, `"revokedAt": 1767235000`, 1)
	srv := newHistoryServer(t, []byte(doc))
	out, err := runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("a"), afterRevocation)))
	wantRefused(t, out, err, "signature does not verify")
}

func TestVerifyAt_EndedEpochWithoutRecordRefused(t *testing.T) {
	c := newAtChain(t, 0, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation)))
	wantRefused(t, out, err, "epoch_end_unrecorded")
}

func TestVerifyAt_FutureEpochRefused(t *testing.T) {
	c := newAtChain(t, 3, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation)))
	wantRefused(t, out, err, "epoch_unknown")
}

func TestVerifyAt_HistoryIssuedBeforeSigningRefused(t *testing.T) {
	// epochhistory-basic was issued at 00:00Z; a signature at 01:00Z is
	// after it, so the document cannot rule out a revocation in between.
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-basic"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation)))
	wantRefused(t, out, err, "history_too_old")
}

func TestVerifyAt_RollbackRefusedGapAccepted(t *testing.T) {
	state := t.TempDir()
	log := newTestLog(t)
	// seqno 1, then 42: a gap, which is normal (each edge-cache miss re-signs).
	early := time.Unix(1767225600, 0).UTC().Add(-time.Hour) // before basic's issuedAt
	c1 := newAtChain(t, 1, early)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-basic"))
	opts := atOpts(srv, log, c1.signAt(t, log, []byte("a"), early))
	opts.stateDir = state
	if out, err := runVerifyAt(t, c1, opts); err != nil {
		t.Fatalf("seqno 1: %v\n%s", err, out)
	}
	c2 := newAtChain(t, 1, beforeRevocation)
	srv.set(fixtureHistory(t, "epochhistory-revoked"))
	opts = atOpts(srv, log, c2.signAt(t, log, []byte("a"), beforeRevocation))
	opts.stateDir = state
	if out, err := runVerifyAt(t, c2, opts); err != nil {
		t.Fatalf("seqno gap 1 -> 42 refused: %v\n%s", err, out)
	}
	// Back to seqno 1: a replayed older document.
	srv.set(fixtureHistory(t, "epochhistory-basic"))
	opts = atOpts(srv, log, c1.signAt(t, log, []byte("a"), early))
	opts.stateDir = state
	out, err := runVerifyAt(t, c1, opts)
	wantRefused(t, out, err, "rollback")
}

// Rollback state is per pinned root, and separate from the CA bundle's: the
// two documents have their own seqno counters.
func TestVerifyAt_RollbackStateIsSeparateFromBundle(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	rootCert := mustReadCert(t, c.rootPath)
	if historyStateID(rootCert) == anchorStateID(rootCert) {
		t.Fatal("epoch history and CA bundle share one rollback counter")
	}
}

func mustReadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	c, err := readLeafCert(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyAt_NoRekorEntrySaysAsOfNow(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	raw, err := os.ReadFile(c.signAt(t, log, []byte("a"), beforeRevocation))
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	_ = json.Unmarshal(raw, &b)
	delete(b["verificationMaterial"].(map[string]any), "tlogEntries")
	stripped, _ := json.Marshal(b)
	dir := t.TempDir()
	writeFile(t, dir, "artifact", []byte("a"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, writeFile(t, dir, "b.json", stripped)))
	wantRefused(t, out, err, "no trusted signing time", "revocation can only be checked as of now")
}

func TestVerifyAt_UntrustedTimeIsLabelled(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))

	// --at alone is refused: the time would be the caller's claim.
	_, err := runVerifyAt(t, c, verifyOptions{authority: srv.URL, client: srv.Client(), claimedAt: beforeRevocation})
	if err == nil || !strings.Contains(err.Error(), "--untrusted-time") {
		t.Fatalf("--at without --untrusted-time: %v", err)
	}

	out, err := runVerifyAt(t, c, verifyOptions{authority: srv.URL, client: srv.Client(), claimedAt: beforeRevocation, untrustedTime: true})
	// Valid, but on a time nobody vouches for: exit 3, not 0 (L3).
	if !isReducedAssurance(err) {
		t.Fatalf("untrusted time: want reduced assurance, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "Certificate valid") {
		t.Fatalf("untrusted-time run is not reported valid:\n%s", out)
	}
	for _, want := range []string{"UNVERIFIED", "not a trusted timestamp"} {
		if !strings.Contains(out, want) {
			t.Errorf("untrusted-time output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Rekor") {
		t.Fatalf("untrusted time is attributed to Rekor:\n%s", out)
	}
}

func TestVerifyAt_FlagCombinations(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	for name, o := range map[string]verifyOptions{
		"untrusted-time without --at":  {untrustedTime: true},
		"--bundle and --at":            {bundlePath: "x", claimedAt: beforeRevocation, untrustedTime: true},
		"--artifact without --bundle":  {artifactPath: "x"},
		"strict without a time":        {strictRevocation: true},
		"--bundle without --artifact":  {bundlePath: "x"},
		"--no-artifact with artifact":  {bundlePath: "x", artifactPath: "y", noArtifact: true},
		"--no-artifact without bundle": {noArtifact: true},
		"max age without strict":       {bundlePath: "x", artifactPath: "y", historyMaxAge: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runVerifyAt(t, c, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestVerifyAt_ArtifactChecked(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	bundle := c.signAt(t, log, []byte("the artifact"), beforeRevocation)
	dir := t.TempDir()

	opts := atOpts(srv, log, bundle)
	opts.artifactPath = writeFile(t, dir, "good", []byte("the artifact"))
	out, err := runVerifyAt(t, c, opts)
	if err != nil || !strings.Contains(out, "Artifact:  matches the logged digest") {
		t.Fatalf("matching artifact: %v\n%s", err, out)
	}

	opts.artifactPath = writeFile(t, dir, "bad", []byte("another artifact"))
	opts.stateDir = ""
	out, err = runVerifyAt(t, c, opts)
	wantRefused(t, out, err, "artifact does not match")
}

func TestVerifyAt_BundleForOtherCertRefused(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	other := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	out, err := runVerifyAt(t, c, atOpts(srv, log, other.signAt(t, log, []byte("a"), beforeRevocation)))
	wantRefused(t, out, err, "not for this certificate")
}

func TestVerifyAt_UntrustedLogRefused(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	opts := atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation))
	opts.rekorLogs = nil // only the public-good log is trusted
	out, err := runVerifyAt(t, c, opts)
	wantRefused(t, out, err, "not from a trusted log")
}

// The published v0.3.1 release: its certificate, the authority's root and
// the bundle with its public-good Rekor entry, against the epochs.json
// production served on 2026-11-04 (the unsigned, pre-notme-6a4f23 shape).
func TestVerifyAt_ReleaseV031(t *testing.T) {
	c := atChain{
		rootPath: filepath.Join(releaseDir, "ca-bundle.cert"),
		leafPath: filepath.Join(releaseDir, "signet-linux-amd64.signet.cert"),
	}
	bundle := filepath.Join(releaseDir, "signet-linux-amd64.sigstore.json")
	unsigned, err := os.ReadFile(filepath.Join(releaseDir, "epochs-unsigned-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := newHistoryServer(t, unsigned)
	// The release binary is not vendored (it is megabytes); the live check
	// covers --artifact against it.
	opts := verifyOptions{authority: srv.URL, client: srv.Client(), bundlePath: bundle, noArtifact: true}

	out, err := runVerifyAt(t, c, opts)
	wantRefused(t, out, err, "does not publish a signed epoch history yet")
	if !strings.Contains(out, "Signed at: 2026-10-28T23:39:48Z (Rekor integrated time") {
		t.Fatalf("output does not report the verified signing time:\n%s", out)
	}

	// The chain itself verifies at the signing time; only revocation is open.
	opts.offline = true
	out, err = runVerifyAt(t, c, opts)
	if !isReducedAssurance(err) {
		t.Fatalf("release chain at its signing time, --offline --no-artifact: want reduced assurance, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "revocation NOT checked") {
		t.Fatalf("--offline output does not say revocation NOT checked:\n%s", out)
	}
}

func isReducedAssurance(err error) bool {
	var r *reducedAssuranceError
	return errors.As(err, &r) && r.ExitCode() == exitReducedAssurance
}

// M1: strict mode refuses any revoked epoch, so a replayed older history
// that predates the revocation must not satisfy it. Strict therefore needs
// a fresh history. epochhistory-basic (issued 00:00Z, epoch 1 current, no
// revocations) is a genuine signed history issued after T and before any
// later revocation R: as of now it is stale and refused.
func TestVerifyAt_StrictRefusesStaleHistory(t *testing.T) {
	early := basicIssuedAt.Add(-time.Hour)
	c := newAtChain(t, 1, early)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-basic"))

	opts := atOpts(srv, log, c.signAt(t, log, []byte("a"), early))
	opts.strictRevocation = true // clock: now, ten months after issuedAt
	out, err := runVerifyAt(t, c, opts)
	wantRefused(t, out, err, "stale", "--history-max-age")

	// The same history, fresh (one minute old), satisfies strict.
	opts = strictOpts(srv, log, c.signAt(t, log, []byte("a"), early), basicIssuedAt)
	if out, err := runVerifyAt(t, c, opts); err != nil {
		t.Fatalf("fresh history refused in strict mode: %v\n%s", err, out)
	}

	// The default bound is notme's 300 s: 301 s is stale, 300 s is not.
	opts.clock = basicIssuedAt.Add(301 * time.Second)
	if out, err := runVerifyAt(t, c, opts); err == nil {
		t.Fatalf("301 s old history accepted in strict mode:\n%s", out)
	}
	opts.clock = basicIssuedAt.Add(300 * time.Second)
	if out, err := runVerifyAt(t, c, opts); err != nil {
		t.Fatalf("300 s old history refused: %v\n%s", err, out)
	}

	// --history-max-age overrides it.
	opts.clock = basicIssuedAt.Add(2 * time.Hour)
	opts.historyMaxAge = 3 * time.Hour
	if out, err := runVerifyAt(t, c, opts); err != nil {
		t.Fatalf("--history-max-age 3h refused a 2h old history: %v\n%s", err, out)
	}

	// Non-strict needs no freshness: a stale history issued after T is sound
	// (every later history must carry any revocation at or before T).
	opts = atOpts(srv, log, c.signAt(t, log, []byte("a"), early))
	if out, err := runVerifyAt(t, c, opts); err != nil {
		t.Fatalf("non-strict refused a stale history: %v\n%s", err, out)
	}
}

// Every mode prints the history's issuedAt and age.
func TestVerifyAt_HistoryIssuedAtPrinted(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	for _, strict := range []bool{false, true} {
		chain, opts := c, atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation))
		if strict {
			// Epoch 2 was never revoked, so strict accepts it.
			chain = newAtChain(t, 2, beforeRevocation)
			opts = strictOpts(srv, log, chain.signAt(t, log, []byte("a"), beforeRevocation), revokedIssuedAt)
		}
		out, err := runVerifyAt(t, chain, opts)
		if err != nil {
			t.Fatalf("strict=%v: %v\n%s", strict, err, out)
		}
		if !strings.Contains(out, "history issued 2026-01-01T03:00:00Z, age ") {
			t.Errorf("strict=%v: output lacks the history issuedAt and age:\n%s", strict, out)
		}
	}
}

// L1: --bundle needs the artifact, or an explicit --no-artifact, which
// marks the header and exits 3.
func TestVerifyAt_NoArtifactIsMarked(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	opts := atOpts(srv, log, c.signAt(t, log, []byte("a"), beforeRevocation))

	opts.artifactPath = ""
	if _, err := runVerifyAt(t, c, opts); err == nil || !strings.Contains(err.Error(), "--no-artifact") {
		t.Fatalf("--bundle without --artifact: %v", err)
	}

	opts.noArtifact = true
	out, err := runVerifyAt(t, c, opts)
	if !isReducedAssurance(err) {
		t.Fatalf("--no-artifact: want reduced assurance, got %v\n%s", err, out)
	}
	header := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
	if !strings.Contains(header, "Certificate valid") || !strings.Contains(header, "artifact NOT checked") {
		t.Fatalf("header does not say artifact NOT checked: %q", header)
	}
}

// L3: exit codes. 0: verified in full. 1: refused. 3: valid with reduced
// assurance (--untrusted-time, --no-artifact, or --offline with --bundle).
// --offline as of now keeps its exit 0.
func TestVerifyAt_ExitCodes(t *testing.T) {
	c := newAtChain(t, 1, beforeRevocation)
	log := newTestLog(t)
	srv := newHistoryServer(t, fixtureHistory(t, "epochhistory-revoked"))
	bundle := c.signAt(t, log, []byte("a"), beforeRevocation)

	if _, err := runVerifyAt(t, c, atOpts(srv, log, bundle)); err != nil {
		t.Fatalf("full verification: %v", err)
	}
	off := atOpts(srv, log, bundle)
	off.offline = true
	if _, err := runVerifyAt(t, c, off); !isReducedAssurance(err) {
		t.Fatalf("--bundle --offline: %v", err)
	}
	if code := exitCodeOf(nil); code != 0 {
		t.Fatalf("nil error exits %d", code)
	}
	if code := exitCodeOf(errors.New("refused")); code != 1 {
		t.Fatalf("refusal exits %d", code)
	}
	if code := exitCodeOf(&reducedAssuranceError{reasons: []string{"x"}}); code != 3 {
		t.Fatalf("reduced assurance exits %d", code)
	}
	// A refusal is never reduced assurance, even with --offline set.
	after := newAtChain(t, 1, afterRevocation)
	r := atOpts(srv, log, after.signAt(t, log, []byte("a"), afterRevocation))
	if _, err := runVerifyAt(t, after, r); err == nil || isReducedAssurance(err) {
		t.Fatalf("revoked: %v", err)
	}

	// Now mode, --offline: unchanged, exit 0.
	ec := newEpochChain(t, 1, 1)
	if out, err := runVerifyForTest(t, ec, verifyOptions{offline: true}); err != nil {
		t.Fatalf("now-mode --offline no longer exits 0: %v\n%s", err, out)
	}
}
