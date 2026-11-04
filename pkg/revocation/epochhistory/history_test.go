package epochhistory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureDir = "testdata/notme-fixtures"

// fixtureRootPub is the key that signed notme's epochhistory fixtures: the
// Ed25519 key whose seed is 0x00..0x1f (notme schema/fixtures/README.md).
const fixtureRootPub = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

func rootKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fixtureRootPub)
	if err != nil {
		t.Fatal(err)
	}
	// The README's key must be the one the seed derives; a fixture signed by
	// another key would otherwise pass against a wrong constant.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, raw) {
		t.Fatal("fixture root key does not match the seed 0x00..0x1f")
	}
	return raw
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name)) // #nosec G304 - test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestFixtures_Vendored checks every vendored file against the sha256 in
// SOURCE (which equal notme's SHA256SUMS), so a fixture edited here to make
// a test pass fails instead.
func TestFixtures_Vendored(t *testing.T) {
	source := string(readFixture(t, "SOURCE"))
	listed := map[string]bool{}
	for _, line := range strings.Split(source, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "sha256" {
			continue
		}
		listed[f[2]] = true
		sum := sha256.Sum256(readFixture(t, f[2]))
		if hex.EncodeToString(sum[:]) != f[1] {
			t.Errorf("%s does not match its sha256 in SOURCE", f[2])
		}
	}
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "SOURCE" && !listed[e.Name()] {
			t.Errorf("%s is not listed in SOURCE", e.Name())
		}
	}
	for _, want := range []string{"epochhistory-basic.json", "epochhistory-revoked.json"} {
		if !listed[want] {
			t.Errorf("%s missing", want)
		}
	}
}

// TestCanonical_MatchesNotme re-encodes each served document and compares
// it with notme's golden signing input, then verifies the signature over it
// under the fixture root: the whole path a verifier takes.
func TestCanonical_MatchesNotme(t *testing.T) {
	for _, name := range []string{"epochhistory-basic", "epochhistory-revoked"} {
		t.Run(name, func(t *testing.T) {
			h, err := Parse(readFixture(t, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonical(h)
			if err != nil {
				t.Fatal(err)
			}
			wantHex := strings.TrimSpace(string(readFixture(t, name+".expected.hex")))
			want, err := hex.DecodeString(wantHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, readFixture(t, name+".bin")) {
				t.Fatal(".expected.hex and .bin disagree")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical mismatch\n got: %x\nwant: %x", got, want)
			}
			if err := VerifySignature(h, rootKey(t)); err != nil {
				t.Fatalf("fixture signature: %v", err)
			}
		})
	}
}

func TestVerifySignature_TamperRefused(t *testing.T) {
	orig := string(readFixture(t, "epochhistory-revoked.json"))
	cases := map[string][2]string{
		// Moving the revocation later would let signatures made after the
		// compromise verify again: the attack the signature exists to stop.
		"revokedAt moved": {`"revokedAt": 1767232800`, `"revokedAt": 1767240000`},
		"currentEpoch":    {`"currentEpoch": 2`, `"currentEpoch": 1`},
		"seqno":           {`"seqno": 42`, `"seqno": 43`},
		"issuedAt":        {`"issuedAt": 1767236400`, `"issuedAt": 1767236401`},
		"reason":          {`"key compromise suspected"`, `"routine"`},
		"revocation epoch": {`"epoch": 1,
      "revokedAt"`, `"epoch": 0,
      "revokedAt"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(orig, c[0]) {
				t.Fatalf("fixture does not contain %q", c[0])
			}
			h, err := Parse([]byte(strings.Replace(orig, c[0], c[1], 1)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifySignature(h, rootKey(t)); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("tampered history verified: %v", err)
			}
		})
	}
	t.Run("revocation dropped", func(t *testing.T) {
		h, err := Parse(readFixture(t, "epochhistory-revoked.json"))
		if err != nil {
			t.Fatal(err)
		}
		h.Revocations = nil
		if err := VerifySignature(h, rootKey(t)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("history with its revocation dropped verified: %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		h, err := Parse(readFixture(t, "epochhistory-revoked.json"))
		if err != nil {
			t.Fatal(err)
		}
		other, _, _ := ed25519.GenerateKey(nil)
		if err := VerifySignature(h, other); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("history verified under another key: %v", err)
		}
	})
}

func TestParse_UnsignedShapeIsNamed(t *testing.T) {
	// What production served before notme-6a4f23 deployed.
	old := `{"epochs":[{"epoch":1,"untilEpoch":null,"keyId":"3b8b237e","publicRawB64":"pqcxqPlJAXr73TqoixsP4nVCZESRKh8vTr7qfJb5s8Y=","retiredAt":null}]}`
	if _, err := Parse([]byte(old)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("old unsigned shape: got %v, want ErrUnsigned", err)
	}
}

func TestParse_Malformed(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":         `nope`,
		"negative seqno":   `{"epochs":[],"revocations":[],"currentEpoch":1,"seqno":-1,"issuedAt":1,"signature":"AA=="}`,
		"fractional":       `{"epochs":[],"revocations":[],"currentEpoch":1.5,"seqno":1,"issuedAt":1,"signature":"AA=="}`,
		"bad key b64":      `{"epochs":[{"epoch":1,"untilEpoch":null,"keyId":"k","publicRawB64":"!!","retiredAt":null}],"revocations":[],"currentEpoch":1,"seqno":1,"issuedAt":1,"signature":"AA=="}`,
		"no revocations":   `{"epochs":[],"currentEpoch":1,"seqno":1,"issuedAt":1,"signature":"AA=="}`,
		"no current epoch": `{"epochs":[],"revocations":[],"seqno":1,"issuedAt":1,"signature":"AA=="}`,
		"no issuedAt":      `{"epochs":[],"revocations":[],"currentEpoch":1,"seqno":1,"signature":"AA=="}`,
		"trailing data":    `{"epochs":[],"revocations":[],"currentEpoch":1,"seqno":1,"issuedAt":1,"signature":"AA=="} {}`,
		"duplicate revocation": `{"epochs":[],"revocations":[{"epoch":1,"revokedAt":5,"reason":"a"},{"epoch":1,"revokedAt":9,"reason":"b"}],` +
			`"currentEpoch":2,"seqno":1,"issuedAt":10,"signature":"AA=="}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

// TestStatusAt is ADR-019 D7 steps 2, 4 and 5, as notme's epochStatusAt,
// over the signed fixture: epoch 1 revoked at 1767232800 ("02:00"), current
// epoch 2, issued at 1767236400 ("03:00").
func TestStatusAt(t *testing.T) {
	h, err := Parse(readFixture(t, "epochhistory-revoked.json"))
	if err != nil {
		t.Fatal(err)
	}
	const revokedAt, issuedAt = 1767232800, 1767236400
	cases := []struct {
		name   string
		epoch  uint64
		t      int64
		strict bool
		want   error
	}{
		{"revoked epoch, signed before the revocation", 1, revokedAt - 1, false, nil},
		{"revoked epoch, signed at the revocation", 1, revokedAt, false, ErrEpochRevoked},
		{"revoked epoch, signed after", 1, revokedAt + 1, false, ErrEpochRevoked},
		{"strict: revoked epoch, signed before", 1, revokedAt - 1, true, ErrEpochRevoked},
		{"strict: revoked epoch, signed after", 1, revokedAt + 1, true, ErrEpochRevoked},
		{"current epoch", 2, revokedAt + 1, false, nil},
		{"strict: current, unrevoked epoch", 2, revokedAt + 1, true, nil},
		{"ended epoch with no record", 0, revokedAt - 1, false, ErrEpochEndUnrecorded},
		{"epoch never issued", 3, revokedAt - 1, false, ErrEpochUnknown},
		{"history issued at T", 2, issuedAt, false, ErrHistoryTooOld},
		{"history issued before T", 2, issuedAt + 1, false, ErrHistoryTooOld},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := StatusAt(h, c.epoch, c.t, c.strict)
			if !errors.Is(got, c.want) || (c.want == nil) != (got == nil) {
				t.Fatalf("StatusAt(epoch %d, t %d, strict %v) = %v, want %v", c.epoch, c.t, c.strict, got, c.want)
			}
		})
	}
}
