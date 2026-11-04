// Package epochhistory verifies an authority's signed epoch history: the
// document notme serves at /.well-known/epochs.json (notme-6a4f23, notme
// ADR-019 D7), and the rule for whether a certificate's CA epoch was revoked
// at a given time.
//
// The live CA bundle (pkg/revocation) answers "is this epoch current now".
// That is no use for a signature made by a five-minute certificate long
// since expired: the epoch has usually moved on for reasons that say nothing
// about that signature. The history says when each ended epoch was REVOKED
// (revocations[].revokedAt), as distinct from a key ROTATED out
// (epochs[].retiredAt, which leaves old signatures good). With a trusted
// signing time T, a certificate's signature stands if its epoch was not
// revoked at or before T.
//
// The document is signed by the authority's root in the CA bundle's
// discipline: RFC 8949 §4.2 canonical CBOR over an integer-keyed map,
// produced here with the same encoder options as revocation.BundleCanonical,
// and checked with the same algorithm registry. Golden vectors with their
// signatures are vendored from notme under testdata/notme-fixtures.
package epochhistory

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/agentic-research/signet/pkg/crypto/algorithm"
)

// Domain is map key 0 of the signing input. No CA bundle encoding has key
// 0, so a bundle signature can never stand in for a history signature.
const Domain = "notme-epoch-history-v1"

var (
	// ErrUnsigned means the document is the epoch list notme served before
	// notme-6a4f23: no signature, no revocations, no currentEpoch. It cannot
	// say when an epoch was revoked, and nothing vouches for it.
	ErrUnsigned = errors.New("the epoch history is not signed (the authority serves the older, unsigned epochs.json)")
	// ErrBadSignature means the signature does not verify under the root.
	ErrBadSignature = errors.New("the epoch history signature does not verify under the pinned root")

	// The verifier rule's refusals (ADR-019 D7; notme epochStatusAt reasons).
	ErrEpochRevoked       = errors.New("epoch_revoked")
	ErrEpochUnknown       = errors.New("epoch_unknown")
	ErrEpochEndUnrecorded = errors.New("epoch_end_unrecorded")
	ErrHistoryTooOld      = errors.New("history_too_old")
)

// KeyEntry is one signing key and the inclusive span of epochs it served.
type KeyEntry struct {
	Epoch      uint64
	UntilEpoch *uint64 // nil: still serving
	KeyID      string
	PublicRaw  []byte
	RetiredAt  *int64 // unix seconds the key was rotated out; nil while live
}

// Revocation is an epoch ended by the authority's revokeEpoch().
type Revocation struct {
	Epoch     uint64
	RevokedAt int64 // unix seconds
	Reason    string
}

// History is a parsed epoch history document.
type History struct {
	Epochs       []KeyEntry
	Revocations  []Revocation
	CurrentEpoch uint64
	Seqno        uint64
	IssuedAt     int64 // unix seconds
	Signature    []byte
}

// MaxDocumentSize is the largest document Parse accepts. notme's document
// grows by one entry per rotation or revocation; a megabyte is thousands.
const MaxDocumentSize = 1 << 20

type wireKey struct {
	Epoch        *uint64 `json:"epoch"`
	UntilEpoch   *uint64 `json:"untilEpoch"`
	KeyID        *string `json:"keyId"`
	PublicRawB64 *string `json:"publicRawB64"`
	RetiredAt    *int64  `json:"retiredAt"`
}

type wireRevocation struct {
	Epoch     *uint64 `json:"epoch"`
	RevokedAt *int64  `json:"revokedAt"`
	Reason    *string `json:"reason"`
}

type wireHistory struct {
	Epochs       []wireKey        `json:"epochs"`
	Revocations  []wireRevocation `json:"revocations"`
	CurrentEpoch *uint64          `json:"currentEpoch"`
	Seqno        *uint64          `json:"seqno"`
	IssuedAt     *int64           `json:"issuedAt"`
	Signature    *string          `json:"signature"`
}

// Parse decodes the served JSON. It checks shape only; call VerifySignature
// before believing any of it. A document with none of the signed fields is
// ErrUnsigned; one with only some of them is malformed.
func Parse(raw []byte) (*History, error) {
	if len(raw) > MaxDocumentSize {
		return nil, fmt.Errorf("epoch history is larger than %d bytes", MaxDocumentSize)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var w wireHistory
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode epoch history: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode epoch history: trailing data after the document")
	}
	if w.Signature == nil && w.Seqno == nil && w.IssuedAt == nil && w.CurrentEpoch == nil && w.Revocations == nil {
		return nil, ErrUnsigned
	}
	switch {
	case w.Signature == nil:
		return nil, errors.New("epoch history has no signature")
	case w.Seqno == nil:
		return nil, errors.New("epoch history has no seqno")
	case w.IssuedAt == nil || *w.IssuedAt < 0:
		return nil, errors.New("epoch history has no valid issuedAt")
	case w.CurrentEpoch == nil:
		return nil, errors.New("epoch history has no currentEpoch")
	case w.Revocations == nil:
		return nil, errors.New("epoch history has no revocations list")
	case w.Epochs == nil:
		return nil, errors.New("epoch history has no epochs list")
	}
	sig, err := base64.StdEncoding.DecodeString(*w.Signature)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("epoch history signature is not standard base64")
	}
	h := &History{
		CurrentEpoch: *w.CurrentEpoch,
		Seqno:        *w.Seqno,
		IssuedAt:     *w.IssuedAt,
		Signature:    sig,
		Epochs:       make([]KeyEntry, 0, len(w.Epochs)),
		Revocations:  make([]Revocation, 0, len(w.Revocations)),
	}
	for i, k := range w.Epochs {
		if k.Epoch == nil || k.KeyID == nil || k.PublicRawB64 == nil {
			return nil, fmt.Errorf("epoch history: epochs[%d] is missing a field", i)
		}
		if k.RetiredAt != nil && *k.RetiredAt < 0 {
			return nil, fmt.Errorf("epoch history: epochs[%d].retiredAt is negative", i)
		}
		pub, err := base64.StdEncoding.DecodeString(*k.PublicRawB64)
		if err != nil {
			return nil, fmt.Errorf("epoch history: epochs[%d].publicRawB64 is not standard base64", i)
		}
		h.Epochs = append(h.Epochs, KeyEntry{
			Epoch: *k.Epoch, UntilEpoch: k.UntilEpoch, KeyID: *k.KeyID, PublicRaw: pub, RetiredAt: k.RetiredAt,
		})
	}
	seen := map[uint64]bool{}
	for i, r := range w.Revocations {
		if r.Epoch == nil || r.RevokedAt == nil || r.Reason == nil || *r.RevokedAt < 0 {
			return nil, fmt.Errorf("epoch history: revocations[%d] is missing or has an invalid field", i)
		}
		// notme writes one row per revoked epoch. Two would make "when was
		// it revoked" ambiguous; refuse rather than pick one.
		if seen[*r.Epoch] {
			return nil, fmt.Errorf("epoch history: epoch %d is revoked twice", *r.Epoch)
		}
		seen[*r.Epoch] = true
		h.Revocations = append(h.Revocations, Revocation{Epoch: *r.Epoch, RevokedAt: *r.RevokedAt, Reason: *r.Reason})
	}
	return h, nil
}

// Canonical returns the signing input: canonical CBOR, integer-keyed,
// signature excluded. Arrays keep the document's order. It must byte-equal
// notme worker/src/epoch-history.ts epochHistoryCanonical; the vendored
// golden vectors are the check.
//
//	0: Domain   1: seqno   2: issuedAt   3: currentEpoch
//	4: [ {1: epoch, 2: untilEpoch|null, 3: keyId, 4: publicRaw, 5: retiredAt|null} ... ]
//	5: [ {1: epoch, 2: revokedAt, 3: reason} ... ]
func Canonical(h *History) ([]byte, error) {
	if h == nil {
		return nil, errors.New("epochhistory: Canonical called with nil history")
	}
	// make(), not a nil slice: CBOR encodes a nil slice as null, and an
	// empty list must be the empty array (0x80) notme signs.
	keys := make([]any, 0, len(h.Epochs))
	for _, k := range h.Epochs {
		var until, retired any
		if k.UntilEpoch != nil {
			until = *k.UntilEpoch
		}
		if k.RetiredAt != nil {
			retired = *k.RetiredAt
		}
		pub := k.PublicRaw
		if pub == nil {
			pub = []byte{}
		}
		keys = append(keys, map[int]any{1: k.Epoch, 2: until, 3: k.KeyID, 4: pub, 5: retired})
	}
	revs := make([]any, 0, len(h.Revocations))
	for _, r := range h.Revocations {
		revs = append(revs, map[int]any{1: r.Epoch, 2: r.RevokedAt, 3: r.Reason})
	}
	message := map[int]any{
		0: Domain,
		1: h.Seqno,
		2: h.IssuedAt,
		3: h.CurrentEpoch,
		4: keys,
		5: revs,
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("epochhistory: build CBOR canonical encoder: %w", err)
	}
	out, err := enc.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("epochhistory: encode canonical bytes: %w", err)
	}
	return out, nil
}

// VerifySignature checks the root's signature over Canonical(h).
func VerifySignature(h *History, root crypto.PublicKey) error {
	if h == nil || len(h.Signature) == 0 {
		return ErrBadSignature
	}
	msg, err := Canonical(h)
	if err != nil {
		return err
	}
	ok, err := algorithm.Verify(root, msg, h.Signature)
	if err != nil {
		return fmt.Errorf("%w: unsupported root key type", ErrBadSignature)
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}

// RevocationOf returns the revocation record for epoch, if any.
func (h *History) RevocationOf(epoch uint64) (Revocation, bool) {
	for _, r := range h.Revocations {
		if r.Epoch == epoch {
			return r, true
		}
	}
	return Revocation{}, false
}

// StatusAt applies the verifier rule (ADR-019 D7 steps 2, 4 and 5; notme
// epochStatusAt) to a certificate of epoch whose signature was made at
// trusted time t, in unix seconds. Call it only on a history whose signature
// verified and whose seqno passed the rollback check. nil means the epoch
// stands at t.
//
//   - t must be strictly before issuedAt: a history issued at or before t
//     cannot know of a revocation between its issuance and t.
//   - an epoch above currentEpoch was never issued under.
//   - a revoked epoch is good only for t < revokedAt; strict refuses it
//     whatever t.
//   - the current epoch, unrevoked, is good.
//   - an ended epoch with no revocation record is refused: the history
//     cannot say when it ended.
func StatusAt(h *History, epoch uint64, t int64, strict bool) error {
	if t >= h.IssuedAt {
		return fmt.Errorf("%w: the history was issued at %s, not after the signing time %s, so it cannot rule out a revocation in between", ErrHistoryTooOld, unix(h.IssuedAt), unix(t))
	}
	if epoch > h.CurrentEpoch {
		return fmt.Errorf("%w: epoch %d is ahead of the authority's current epoch %d", ErrEpochUnknown, epoch, h.CurrentEpoch)
	}
	if r, ok := h.RevocationOf(epoch); ok {
		if strict {
			return fmt.Errorf("%w: epoch %d was revoked at %s (%q), and strict mode refuses any revoked epoch", ErrEpochRevoked, epoch, unix(r.RevokedAt), r.Reason)
		}
		if t >= r.RevokedAt {
			return fmt.Errorf("%w: epoch %d was revoked at %s (%q), at or before the signing time %s", ErrEpochRevoked, epoch, unix(r.RevokedAt), r.Reason, unix(t))
		}
		return nil
	}
	if epoch == h.CurrentEpoch {
		return nil
	}
	return fmt.Errorf("%w: epoch %d ended (current is %d) with no revocation record, so the history cannot say when it ended", ErrEpochEndUnrecorded, epoch, h.CurrentEpoch)
}

func unix(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) }
