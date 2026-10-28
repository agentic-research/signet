package revocation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentic-research/signet/pkg/revocation/types"
)

// TestBundleCanonical_NilBundle asserts that BundleCanonical refuses a nil
// bundle rather than panicking on the field accesses.
func TestBundleCanonical_NilBundle(t *testing.T) {
	if _, err := BundleCanonical(nil); err == nil {
		t.Fatal("BundleCanonical(nil) should error, got nil")
	}
}

// TestBundleCanonical_Deterministic asserts the function returns identical
// bytes for identical input. Underlying RFC 8949 §4.2 canonical CBOR is
// deterministic by construction; this test pins the property at the helper
// boundary so a future refactor can't silently break it.
func TestBundleCanonical_Deterministic(t *testing.T) {
	bundle := &types.CABundle{
		Epoch:     7,
		Seqno:     3,
		Keys:      map[string][]byte{"kid1": {0x01, 0x02, 0x03}, "kid2": {0x04, 0x05, 0x06}},
		KeyID:     "kid1",
		PrevKeyID: "",
		IssuedAt:  1_700_000_000,
		Signature: []byte("ignored"),
	}
	a, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BundleCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic encoding: %x vs %x", a, b)
	}
}

// TestBundleCanonical_SignatureExcluded asserts that the Signature field is
// not part of the canonical bytes. Changing the signature must not change
// the verifier's input; otherwise verify would never succeed.
func TestBundleCanonical_SignatureExcluded(t *testing.T) {
	base := func() *types.CABundle {
		return &types.CABundle{
			Epoch:     1,
			Seqno:     1,
			Keys:      map[string][]byte{"kid": {0xab, 0xcd}},
			KeyID:     "kid",
			IssuedAt:  1234,
			Signature: []byte("first"),
		}
	}
	a, err := BundleCanonical(base())
	if err != nil {
		t.Fatal(err)
	}
	b2 := base()
	b2.Signature = []byte("different")
	b, err := BundleCanonical(b2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("Signature change altered canonical bytes: %x vs %x", a, b)
	}
}

// TestBundleCanonical_CrossRuntimeFixtures asserts signet's encoding against
// notme's shared ADR-010 fixtures (signet-0454a2), the same files notme's
// TypeScript test and ley-line-open's Rust test load. Three implementations
// must produce byte-identical canonical bytes, or cross-language CABundle
// signatures silently fail to verify.
//
// The files are vendored under testdata/notme-fixtures by
// scripts/testing/sync_notme_fixtures.sh, which records the notme commit and
// each file's sha256 in SOURCE. Hashes are checked first, so a fixture edited
// here to make this test pass fails instead. Never edit the expected bytes;
// the encoding is the contract.
//
// Drift: these fixtures are also the canary for a fxamacker/cbor upgrade that
// would change canonical-encoding behavior. If the bytes diverge, any signed
// bundle in the wild produced by the old encoder fails under the new one.
func TestBundleCanonical_CrossRuntimeFixtures(t *testing.T) {
	const dir = "testdata/notme-fixtures"
	verifyVendoredFixtures(t, dir)

	inputs, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, in := range inputs {
		name := strings.TrimSuffix(filepath.Base(in), ".json")
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			bundle := loadFixtureBundle(t, in)
			got, err := BundleCanonical(bundle)
			if err != nil {
				t.Fatal(err)
			}

			wantHex, err := os.ReadFile(filepath.Join(dir, name+".expected.hex"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(strings.TrimSpace(string(wantHex)))
			if err != nil {
				t.Fatal(err)
			}
			wantBin, err := os.ReadFile(filepath.Join(dir, name+".bin"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, wantBin) {
				t.Fatalf("%s: .expected.hex and .bin disagree; re-sync the fixtures", name)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("cross-runtime fixture %s mismatch\n got: %s\nwant: %s",
					name, hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
	// cabundle-multikey lists keys out of canonical order, so passing it proves
	// RFC 8949 §4.2 sorting rather than insertion order. Require both.
	for _, required := range []string{"cabundle-basic", "cabundle-multikey"} {
		if !seen[required] {
			t.Errorf("fixture %s missing from %s", required, dir)
		}
	}
}

// fixtureBundle is notme's fixture JSON shape (schema/fixtures/README.md):
// keys map kid to standard-base64 key bytes; there is no signature field.
type fixtureBundle struct {
	Epoch     uint64            `json:"epoch"`
	Seqno     uint64            `json:"seqno"`
	Keys      map[string][]byte `json:"keys"`
	KeyID     string            `json:"keyId"`
	PrevKeyID string            `json:"prevKeyId"`
	IssuedAt  int64             `json:"issuedAt"`
}

func loadFixtureBundle(t *testing.T, path string) *types.CABundle {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return &types.CABundle{
		Epoch:     f.Epoch,
		Seqno:     f.Seqno,
		Keys:      f.Keys,
		KeyID:     f.KeyID,
		PrevKeyID: f.PrevKeyID,
		IssuedAt:  f.IssuedAt,
		// A decoy: the signature is excluded from the signing input.
		Signature: []byte("ignored, must not affect canonical bytes"),
	}
}

// verifyVendoredFixtures checks every file in dir against the sha256 recorded
// in SOURCE, and that SOURCE lists every file present.
func verifyVendoredFixtures(t *testing.T, dir string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(dir, "SOURCE"))
	if err != nil {
		t.Fatalf("read SOURCE (run scripts/testing/sync_notme_fixtures.sh): %v", err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(source), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "sha256" {
			continue
		}
		name := fields[2]
		listed[name] = true
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != fields[1] {
			t.Errorf("%s does not match the sha256 recorded in SOURCE: edited by hand? re-run scripts/testing/sync_notme_fixtures.sh", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "SOURCE" && !listed[e.Name()] {
			t.Errorf("%s is in %s but not in SOURCE", e.Name(), dir)
		}
	}
}
