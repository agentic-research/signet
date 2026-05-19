package git

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCertHexFingerprint_NilCert(t *testing.T) {
	got := certHexFingerprint(nil)
	want := strings.Repeat("0", 40)
	if got != want {
		t.Fatalf("nil cert: got %q, want all-zero fingerprint %q", got, want)
	}
}

func TestCertHexFingerprint_EmptyRaw(t *testing.T) {
	got := certHexFingerprint(&x509.Certificate{})
	want := strings.Repeat("0", 40)
	if got != want {
		t.Fatalf("empty Raw: got %q, want all-zero fingerprint %q", got, want)
	}
}

func TestCertHexFingerprint_DeterministicSHA1(t *testing.T) {
	cert := mintTestCert(t)
	got := certHexFingerprint(cert)

	expected := sha1.Sum(cert.Raw) // #nosec G401 — parity with certHexFingerprint's documented use; not security
	want := hex.EncodeToString(expected[:])
	if got != want {
		t.Fatalf("fingerprint mismatch:\n got: %s\nwant: %s", got, want)
	}
	if len(got) != 40 {
		t.Fatalf("expected 40-char SHA-1 hex, got %d chars", len(got))
	}

	again := certHexFingerprint(cert)
	if again != got {
		t.Fatalf("fingerprint not deterministic across calls: %s vs %s", got, again)
	}
}

func TestEmitStatus_StatusFdZero_NoOp(t *testing.T) {
	emitStatus(0, "[GNUPG:] SHOULD_NOT_APPEAR")
}

func TestEmitStatus_StatusFdNegative_NoOp(t *testing.T) {
	emitStatus(-1, "[GNUPG:] SHOULD_NOT_APPEAR")
}

func TestEmitStatus_WritesLineToFd(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	line := "[GNUPG:] BEGIN_SIGNING"
	emitStatus(int(w.Fd()), line)

	scanner := bufio.NewScanner(r)
	done := make(chan struct{})
	var got string
	go func() {
		if scanner.Scan() {
			got = scanner.Text()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for emitStatus to write the line")
	}

	if got != line {
		t.Fatalf("got %q, want %q", got, line)
	}
}

// mintTestCert builds a self-signed Ed25519 cert good enough to exercise
// fingerprint code paths. Not a CA cert — just something with a populated
// cert.Raw.
func mintTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
