package revocation

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/agentic-research/signet/pkg/revocation/types"
)

// BundleCanonical produces the CBOR canonical-bytes signing input for a CABundle.
//
// Per signet ADR-002 §2.3 + notme ADR-010, the bytes that get Ed25519-signed
// are produced via RFC 8949 §4.2 deterministic CBOR encoding over an
// integer-keyed map:
//
//	1: bundle.Epoch
//	2: bundle.Seqno
//	3: bundle.Keys
//	4: bundle.KeyID
//	5: bundle.PrevKeyID
//	6: bundle.IssuedAt
//
// The Signature field is intentionally excluded — it is what gets verified
// against this byte sequence, not part of the sign input.
//
// Cross-runtime contract: the bytes returned here MUST byte-equal
// notme/worker/src/revocation.ts bundleCanonical() and
// cloister/src/storage/bundle-canonical.ts bundleCanonical() for the same
// logical input. The pinned cross-runtime fixture lives in
// canonical_test.go (TestBundleCanonical_CrossRuntimeFixture) and matches
// the 25-byte sequence pinned by notme/worker/src/__tests__/bundle-canonical.test.ts.
//
// A fxamacker/cbor library upgrade that changes encoding behavior will
// break this byte-equality contract silently. The cross-runtime fixture
// test is the canary — run pkg/revocation/... before bumping the cbor
// dependency.
func BundleCanonical(bundle *types.CABundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("revocation: BundleCanonical called with nil bundle")
	}
	message := map[int]any{
		1: bundle.Epoch,
		2: bundle.Seqno,
		3: bundle.Keys,
		4: bundle.KeyID,
		5: bundle.PrevKeyID,
		6: bundle.IssuedAt,
	}
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("revocation: build CBOR canonical encoder: %w", err)
	}
	canonical, err := encMode.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("revocation: encode bundle canonical bytes: %w", err)
	}
	return canonical, nil
}
