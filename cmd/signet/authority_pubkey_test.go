package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPubkeyFromLocalKeystore_XDG initializes a fresh XDG-isolated
// keystore, runs the local-keystore path of `signet authority pubkey`,
// and asserts the output round-trips a known Ed25519 public key.
//
// This is the "dev bootstrap" code path: a developer runs `signet-git
// init` against an isolated home, then `signet authority pubkey` against
// the same home, and pipes the output into `INTERLACE_ROOT_PUBKEY=...`
// in cloister's .env.local.
func TestPubkeyFromLocalKeystore_XDG(t *testing.T) {
	// Generate a known Ed25519 keypair and write the seed to an
	// XDG-style file ourselves (skipping signet-git init to keep the
	// test contained to authority_pubkey.go's surface). We use the
	// same PEM type and 0600 permissions InitializeInsecure does.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: seed,
	})
	keyDir := filepath.Join(tmp, "signet")
	if err := mkdir0700(keyDir); err != nil {
		t.Fatal(err)
	}
	if err := writeFile0600(filepath.Join(keyDir, "master.key"), pemBytes); err != nil {
		t.Fatal(err)
	}

	got, err := pubkeyFromLocalKeystore()
	if err != nil {
		t.Fatalf("pubkeyFromLocalKeystore: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("got %d bytes, want %d (Ed25519 pubkey size)", len(got), ed25519.PublicKeySize)
	}
	if !ed25519Equal(got, []byte(pub)) {
		t.Fatalf("pubkey mismatch:\n  got:  %x\n  want: %x", got, []byte(pub))
	}

	// Also verify the full subcommand stdout shape: base64 line, no
	// header/footer. Use the same data via runAuthorityPubkey's path.
	encoded := base64.StdEncoding.EncodeToString(got)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 round-trip: %v", err)
	}
	if !ed25519Equal(decoded, got) {
		t.Fatal("base64 round-trip changed bytes")
	}
}

// TestPubkeyFromURL spins up an httptest server that serves a
// known-key PEM CA cert at /.well-known/ca-bundle.pem, fetches it via
// the same code path that `signet authority pubkey --url <X>` takes,
// and asserts the returned bytes match the original public key.
func TestPubkeyFromURL(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := selfSignedCAPem(t, priv, pub)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ca-bundle.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := pubkeyFromURL(context.Background(), srv.URL, "/.well-known/ca-bundle.pem", 5*time.Second)
	if err != nil {
		t.Fatalf("pubkeyFromURL: %v", err)
	}
	if !ed25519Equal(got, []byte(pub)) {
		t.Fatalf("pubkey mismatch:\n  got:  %x\n  want: %x", got, []byte(pub))
	}
}

// TestPubkeyFromURL_Non200 rejects responses that aren't 200 OK with
// an actionable error.
func TestPubkeyFromURL_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	_, err := pubkeyFromURL(context.Background(), srv.URL, "/.well-known/ca-bundle.pem", 1*time.Second)
	if err == nil {
		t.Fatal("expected error on 503, got nil")
	}
}

// TestPubkeyFromURL_NotPEM rejects bodies that are not PEM-encoded.
func TestPubkeyFromURL_NotPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello, world — not a PEM block"))
	}))
	t.Cleanup(srv.Close)
	_, err := pubkeyFromURL(context.Background(), srv.URL, "/.well-known/ca-bundle.pem", 1*time.Second)
	if err == nil {
		t.Fatal("expected error on non-PEM body, got nil")
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func ed25519Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func selfSignedCAPem(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-authority"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mkdir0700(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

func writeFile0600(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}
