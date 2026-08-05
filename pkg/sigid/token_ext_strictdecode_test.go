package sigid

import (
	"encoding/hex"
	"strings"
	"testing"
)

// sigid decodes token wire bytes independently of signet.Unmarshal. Both must
// use signet.TokenDecMode: under the library default, a generic map decode
// keeps the LAST occurrence of a duplicated key while a struct decode keeps
// the FIRST, so the two packages could disagree about what a token says —
// e.g. sigid reading an attacker's confirmation ID while signet reads the
// legitimate one. This pins that sigid rejects what signet rejects.
func TestTokenBytesDecodeIsStrictAcrossPackages(t *testing.T) {
	// Golden current-format token (8 pairs) widened to 9 with key 1 repeated.
	const goldenCurrentHex = "a801757369676e65742d6973737565722d63757272656e740358205b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b041a65ec88ac051a65ec8780061a65ec87800750cacacacacacacacacacacacacacacaca095820cfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcf0d5071717171717171717171717171717171"
	raw, err := hex.DecodeString("a9" + goldenCurrentHex[2:] + "0163646966")
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}

	if _, err := ChainFromToken(raw); err == nil {
		t.Fatal("ChainFromToken accepted a duplicate-key token payload")
	} else if !strings.Contains(err.Error(), "duplicate map key") {
		t.Logf("rejected (not by the duplicate-key rule): %v", err)
	}
}
