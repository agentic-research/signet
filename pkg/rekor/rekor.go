// Package rekor establishes a trusted signing time from a Sigstore bundle:
// the integrated time of its Rekor (v1) transparency log entry, verified.
//
// The time is believed because the log signed it, not because the signer
// or the verifier's clock says so. VerifyBundle checks, for a bundle and the
// certificate it is meant to be about:
//
//   - the log entry is from a log the caller trusts (by default the
//     public-good Rekor, whose key is pinned below);
//   - the signed entry timestamp (SET): the log's signature over the entry
//     body, its integrated time, log id and index. The SET is the only thing
//     that covers the integrated time, so it is required;
//   - the inclusion proof: the entry's leaf hash, with the proof's hashes,
//     yields the proof's root (RFC 6962), and a checkpoint signed by the same
//     log commits to that root and tree size;
//   - the entry is a hashedrekord whose certificate is this certificate,
//     whose signature and digest are the bundle's, and whose signature
//     verifies under the certificate's key;
//   - optionally, the artifact hashes to the logged digest.
//
// It does not check the certificate chain, its validity window, or identity:
// that is the caller's, at the returned time.
//
// Why not sigstore-go: it brings TUF, a protobuf runtime and a tree of
// transparency-log modules to answer one question signet asks here. These
// checks are a few hundred lines of the standard library, and the published
// v0.3.1 release bundle is a test vector.
package rekor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrNoTlogEntry means the bundle has no transparency log entry, so
	// there is no trusted time for its signature.
	ErrNoTlogEntry = errors.New("the bundle has no Rekor transparency log entry")
	// ErrNoTrustedEntry means every log entry is from a log not trusted.
	ErrNoTrustedEntry = errors.New("the bundle's Rekor entry is not from a trusted log")
	// ErrCertMismatch means the bundle, or its log entry, is about a
	// different certificate.
	ErrCertMismatch = errors.New("the bundle is not for this certificate")
	// ErrArtifactMismatch means the artifact does not hash to the logged digest.
	ErrArtifactMismatch = errors.New("the artifact does not match the digest in the Rekor entry")
)

// publicGoodRekorKey is the public-good Rekor v1 log key (rekor.sigstore.dev,
// log id c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d),
// as published in the Sigstore TUF trusted_root.json, valid from 2021-01-12.
const publicGoodRekorKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
`

// publicGoodValidFrom is the start of the public-good key's validFor in the
// Sigstore TUF trusted_root.json. It has no end there; when Sigstore retires
// the key, set publicGoodValidUntil to the end the trusted root publishes.
var (
	publicGoodValidFrom  = time.Date(2021, 1, 12, 11, 53, 27, 0, time.UTC)
	publicGoodValidUntil time.Time
)

// Log is a trusted transparency log: its key, and the window in which an
// entry's integrated time may fall (a trusted root's validFor). An entry
// outside the window is refused, so a retired (or compromised and retired)
// key cannot vouch for a later time.
type Log struct {
	Key        crypto.PublicKey
	ValidFrom  time.Time // required: a log with no start is refused
	ValidUntil time.Time // zero: no end
}

// PublicGoodLog returns the public-good Rekor log, with its validity window.
func PublicGoodLog() Log {
	block, _ := pem.Decode([]byte(publicGoodRekorKey))
	if block == nil {
		panic("rekor: embedded public-good key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("rekor: embedded public-good key: " + err.Error())
	}
	return Log{Key: k, ValidFrom: publicGoodValidFrom, ValidUntil: publicGoodValidUntil}
}

// ErrOutsideLogValidity means the entry's integrated time is outside the
// window in which its log's key is trusted.
var ErrOutsideLogValidity = errors.New("the Rekor entry's integrated time is outside its log key's validity window")

// Options configures VerifyBundle.
type Options struct {
	// Logs are the trusted logs. Empty means the public-good Rekor.
	Logs []Log
	// Artifact, when set, is read and checked against the logged digest.
	Artifact io.Reader
}

// Result is what a verified bundle establishes.
type Result struct {
	IntegratedTime  time.Time // the log's timestamp for the entry
	LogIndex        int64
	LogID           string // hex
	ArtifactChecked bool
}

// jsonInt reads an int64 written either as a JSON number or, as protobuf
// JSON writes 64-bit integers, as a decimal string.
type jsonInt int64

func (n *jsonInt) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}
	*n = jsonInt(v)
	return nil
}

type rawCert struct {
	RawBytes []byte `json:"rawBytes"`
}

type inclusionProof struct {
	LogIndex   *jsonInt `json:"logIndex"`
	RootHash   []byte   `json:"rootHash"`
	TreeSize   *jsonInt `json:"treeSize"`
	Hashes     [][]byte `json:"hashes"`
	Checkpoint struct {
		Envelope string `json:"envelope"`
	} `json:"checkpoint"`
}

type tlogEntry struct {
	LogIndex *jsonInt `json:"logIndex"`
	LogID    struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   *jsonInt `json:"integratedTime"`
	InclusionPromise *struct {
		SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof    *inclusionProof `json:"inclusionProof"`
	CanonicalizedBody []byte          `json:"canonicalizedBody"`
}

type bundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate          *rawCert `json:"certificate"`
		X509CertificateChain *struct {
			Certificates []rawCert `json:"certificates"`
		} `json:"x509CertificateChain"`
		TlogEntries []tlogEntry `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
}

type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   []byte `json:"content"`
			PublicKey struct {
				Content []byte `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// maxBundle bounds what VerifyBundle parses; release bundles are a few KB.
const maxBundle = 1 << 20

// MaxBundleSize is the largest bundle VerifyBundle accepts.
const MaxBundleSize = maxBundle

// VerifyBundle verifies raw, a Sigstore bundle (JSON, v0.1 to v0.3), as a
// record that leaf's key signed at a time a trusted log vouches for.
func VerifyBundle(raw []byte, leaf *x509.Certificate, opts Options) (*Result, error) {
	if leaf == nil {
		return nil, errors.New("rekor: no certificate to verify the bundle against")
	}
	if len(raw) > maxBundle {
		return nil, fmt.Errorf("rekor: bundle is larger than %d bytes", maxBundle)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("rekor: decode bundle: %w", err)
	}
	if !strings.HasPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle") {
		return nil, fmt.Errorf("rekor: not a Sigstore bundle (mediaType %q)", b.MediaType)
	}

	// The bundle must be about this certificate.
	var bundleCert []byte
	switch vm := b.VerificationMaterial; {
	case vm.Certificate != nil:
		bundleCert = vm.Certificate.RawBytes
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0:
		bundleCert = vm.X509CertificateChain.Certificates[0].RawBytes
	}
	if len(bundleCert) == 0 {
		return nil, fmt.Errorf("%w: the bundle carries no signing certificate", ErrCertMismatch)
	}
	if !bytes.Equal(bundleCert, leaf.Raw) {
		return nil, fmt.Errorf("%w: its signing certificate is a different one", ErrCertMismatch)
	}
	if b.MessageSignature == nil {
		return nil, errors.New("rekor: the bundle has no message signature (DSSE bundles are not supported)")
	}

	entry, log, logID, err := pickEntry(b.VerificationMaterial.TlogEntries, opts.Logs)
	if err != nil {
		return nil, err
	}
	if err := verifyEntryLogged(entry, log.Key, logID); err != nil {
		return nil, err
	}
	// The SET has verified, so the integrated time is the log's own claim.
	// It counts only inside the window the log's key is trusted for.
	integrated := time.Unix(int64(*entry.IntegratedTime), 0).UTC()
	if log.ValidFrom.IsZero() {
		return nil, fmt.Errorf("%w: the trusted log has no validity start", ErrOutsideLogValidity)
	}
	if integrated.Before(log.ValidFrom) || (!log.ValidUntil.IsZero() && integrated.After(log.ValidUntil)) {
		return nil, fmt.Errorf("%w: %s is not within %s to %s", ErrOutsideLogValidity,
			integrated.Format(time.RFC3339), log.ValidFrom.UTC().Format(time.RFC3339), windowEnd(log.ValidUntil))
	}

	// The entry: a hashedrekord of this cert, this signature, this digest.
	if entry.KindVersion.Kind != "hashedrekord" || entry.KindVersion.Version != "0.0.1" {
		return nil, fmt.Errorf("rekor: unsupported entry kind %s/%s (want hashedrekord/0.0.1)", entry.KindVersion.Kind, entry.KindVersion.Version)
	}
	var body hashedRekord
	if err := json.Unmarshal(entry.CanonicalizedBody, &body); err != nil {
		return nil, fmt.Errorf("rekor: decode entry body: %w", err)
	}
	if body.Kind != "hashedrekord" || body.APIVersion != "0.0.1" {
		return nil, fmt.Errorf("rekor: entry body is %s/%s, not hashedrekord/0.0.1", body.Kind, body.APIVersion)
	}
	certBlock, _ := pem.Decode(body.Spec.Signature.PublicKey.Content)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || !bytes.Equal(certBlock.Bytes, leaf.Raw) {
		return nil, fmt.Errorf("%w: the log entry names a different signing certificate", ErrCertMismatch)
	}
	sig := body.Spec.Signature.Content
	if len(sig) == 0 || !bytes.Equal(sig, b.MessageSignature.Signature) {
		return nil, errors.New("rekor: the bundle's signature is not the one in the log entry")
	}
	digest, err := hex.DecodeString(body.Spec.Data.Hash.Value)
	if err != nil || len(digest) == 0 {
		return nil, errors.New("rekor: the log entry's digest is not hex")
	}
	newHash, hashID, err := digestAlgorithm(body.Spec.Data.Hash.Algorithm, b.MessageSignature.MessageDigest.Algorithm)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, b.MessageSignature.MessageDigest.Digest) || len(digest) != newHash().Size() {
		return nil, errors.New("rekor: the bundle's digest is not the one in the log entry")
	}
	if err := verifyDigestSignature(leaf.PublicKey, hashID, digest, sig); err != nil {
		return nil, err
	}

	res := &Result{
		IntegratedTime: integrated,
		LogIndex:       int64(*entry.LogIndex),
		LogID:          hex.EncodeToString(logID),
	}
	if opts.Artifact != nil {
		h := newHash()
		if _, err := io.Copy(h, opts.Artifact); err != nil {
			return nil, fmt.Errorf("rekor: read artifact: %w", err)
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), digest) != 1 {
			return nil, ErrArtifactMismatch
		}
		res.ArtifactChecked = true
	}
	return res, nil
}

func windowEnd(t time.Time) string {
	if t.IsZero() {
		return "no end"
	}
	return t.UTC().Format(time.RFC3339)
}

// pickEntry returns the first entry from a trusted log, with its log and id.
func pickEntry(entries []tlogEntry, logs []Log) (*tlogEntry, Log, []byte, error) {
	if len(entries) == 0 {
		return nil, Log{}, nil, ErrNoTlogEntry
	}
	if len(logs) == 0 {
		logs = []Log{PublicGoodLog()}
	}
	for i := range entries {
		for _, l := range logs {
			id, err := keyID(l.Key)
			if err != nil {
				return nil, Log{}, nil, err
			}
			if bytes.Equal(id, entries[i].LogID.KeyID) {
				return &entries[i], l, id, nil
			}
		}
	}
	return nil, Log{}, nil, ErrNoTrustedEntry
}

// verifyEntryLogged checks the SET and the inclusion proof with its
// checkpoint, all under the log's key.
func verifyEntryLogged(entry *tlogEntry, logKey crypto.PublicKey, logID []byte) error {
	if entry.LogIndex == nil || *entry.LogIndex < 0 || entry.IntegratedTime == nil || *entry.IntegratedTime <= 0 {
		return errors.New("rekor: the log entry has no valid log index or integrated time")
	}
	if len(entry.CanonicalizedBody) == 0 {
		return errors.New("rekor: the log entry has no body")
	}

	// The SET: the log's signature over the body, time, id and index. The
	// payload is RFC 8785 canonical JSON; for these four fields (sorted keys,
	// integers, a base64 string and a hex string) that is what
	// encoding/json writes for a map.
	if entry.InclusionPromise == nil || len(entry.InclusionPromise.SignedEntryTimestamp) == 0 {
		return errors.New("rekor: the log entry has no signed entry timestamp, so its integrated time is not signed")
	}
	setPayload, err := json.Marshal(map[string]any{
		"body":           base64.StdEncoding.EncodeToString(entry.CanonicalizedBody),
		"integratedTime": int64(*entry.IntegratedTime),
		"logID":          hex.EncodeToString(logID),
		"logIndex":       int64(*entry.LogIndex),
	})
	if err != nil {
		return err
	}
	if !verifyLogSignature(logKey, setPayload, entry.InclusionPromise.SignedEntryTimestamp) {
		return errors.New("rekor: the signed entry timestamp does not verify under the log key")
	}

	// Inclusion: the leaf is in the tree a signed checkpoint commits to.
	p := entry.InclusionProof
	if p == nil {
		return errors.New("rekor: the log entry has no inclusion proof")
	}
	if p.LogIndex == nil || p.TreeSize == nil || *p.LogIndex < 0 || *p.TreeSize <= 0 {
		return errors.New("rekor: the inclusion proof has no valid index or tree size")
	}
	index, size := uint64(*p.LogIndex), uint64(*p.TreeSize) // #nosec G115 - both checked non-negative above
	root, err := rootFromInclusionProof(index, size, hashLeaf(entry.CanonicalizedBody), p.Hashes)
	if err != nil {
		return fmt.Errorf("rekor: inclusion proof: %w", err)
	}
	if !bytes.Equal(root, p.RootHash) {
		return errors.New("rekor: the inclusion proof does not lead to its root hash")
	}
	if err := verifyCheckpoint(p.Checkpoint.Envelope, logKey, logID, size, root); err != nil {
		return fmt.Errorf("rekor: checkpoint: %w", err)
	}
	return nil
}

// keyID is a log's id: the SHA-256 of its key's SubjectPublicKeyInfo.
func keyID(k crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("rekor: log key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return sum[:], nil
}

// verifyLogSignature checks a log's signature over msg: ECDSA over its
// SHA-256, or Ed25519 over msg itself.
func verifyLogSignature(k crypto.PublicKey, msg, sig []byte) bool {
	switch pub := k.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	default:
		return false
	}
}

// digestAlgorithm maps the entry's hash name, which must agree with the
// bundle's, to a hash.
func digestAlgorithm(entryAlg, bundleAlg string) (func() hash.Hash, crypto.Hash, error) {
	type alg struct {
		bundle string
		new    func() hash.Hash
		id     crypto.Hash
	}
	known := map[string]alg{
		"sha256": {"SHA2_256", sha256.New, crypto.SHA256},
		"sha384": {"SHA2_384", sha512.New384, crypto.SHA384},
		"sha512": {"SHA2_512", sha512.New, crypto.SHA512},
	}
	a, ok := known[entryAlg]
	if !ok {
		return nil, 0, fmt.Errorf("rekor: unsupported digest algorithm %q", entryAlg)
	}
	if bundleAlg != a.bundle {
		return nil, 0, fmt.Errorf("rekor: the bundle's digest algorithm %q is not the log entry's %q", bundleAlg, entryAlg)
	}
	return a.new, a.id, nil
}

// verifyDigestSignature checks the artifact signature over its digest, as
// Rekor did before logging it: ECDSA over the digest, or Ed25519ph (the
// pre-hashed variant, SHA-512) for an Ed25519 key.
func verifyDigestSignature(k crypto.PublicKey, h crypto.Hash, digest, sig []byte) error {
	switch pub := k.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("rekor: the artifact signature does not verify under the certificate's key")
		}
	case ed25519.PublicKey:
		if h != crypto.SHA512 {
			return errors.New("rekor: an Ed25519 signature over a digest must use SHA-512 (Ed25519ph)")
		}
		if err := ed25519.VerifyWithOptions(pub, digest, sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
			return errors.New("rekor: the artifact signature does not verify under the certificate's key")
		}
	default:
		return fmt.Errorf("rekor: unsupported certificate key type %T", k)
	}
	return nil
}

// verifyCheckpoint checks a signed-note checkpoint: one signature line by
// the log's key (key hash = first four bytes of its log id) over the note
// text, and a body that commits to size and root.
func verifyCheckpoint(envelope string, k crypto.PublicKey, logID []byte, size uint64, root []byte) error {
	i := strings.Index(envelope, "\n\n")
	if i < 0 {
		return errors.New("not a signed note")
	}
	text, sigs := envelope[:i+1], envelope[i+2:]
	signed := false
	for _, line := range strings.Split(sigs, "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(raw) < 5 || !bytes.Equal(raw[:4], logID[:4]) {
			continue
		}
		if verifyLogSignature(k, []byte(text), raw[4:]) {
			signed = true
			break
		}
	}
	if !signed {
		return errors.New("not signed by the log key")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return errors.New("checkpoint body is short")
	}
	gotSize, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || gotSize != size {
		return fmt.Errorf("checkpoint tree size %q is not the proof's %d", lines[1], size)
	}
	gotRoot, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || !bytes.Equal(gotRoot, root) {
		return errors.New("checkpoint root hash is not the proof's")
	}
	return nil
}

// RFC 6962 §2.1 hashing.
func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

func hashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// rootFromInclusionProof computes the tree root from a leaf hash and its
// audit path (RFC 6962 §2.1.1; the algorithm of transparency-dev/merkle's
// proof.RootFromInclusionProof).
func rootFromInclusionProof(index, size uint64, leafHash []byte, proof [][]byte) ([]byte, error) {
	if index >= size {
		return nil, fmt.Errorf("index %d is beyond tree size %d", index, size)
	}
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> inner)
	if len(proof) != inner+border {
		return nil, fmt.Errorf("proof has %d hashes, want %d", len(proof), inner+border)
	}
	for _, h := range proof {
		if len(h) != sha256.Size {
			return nil, errors.New("proof hash is not 32 bytes")
		}
	}
	res := leafHash
	for i, h := range proof[:inner] {
		if (index>>i)&1 == 0 {
			res = hashChildren(res, h)
		} else {
			res = hashChildren(h, res)
		}
	}
	for _, h := range proof[inner:] {
		res = hashChildren(h, res)
	}
	return res, nil
}
