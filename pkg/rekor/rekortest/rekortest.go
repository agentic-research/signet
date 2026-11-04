// Package rekortest builds Sigstore bundles logged in a fake Rekor, for
// tests: a log key, a signed entry timestamp, a one-leaf inclusion proof and
// a signed checkpoint, all in the shapes the public-good log emits. Nothing
// here talks to a network.
package rekortest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"
)

// Log is a fake transparency log with its own ECDSA P-256 key, like the
// public-good Rekor.
type Log struct {
	Key   *ecdsa.PrivateKey
	logID []byte
}

// NewLog makes a log with a fresh key.
func NewLog() (*Log, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	id := sha256.Sum256(spki)
	return &Log{Key: k, logID: id[:]}, nil
}

// PublicKey is the log's verification key.
func (l *Log) PublicKey() crypto.PublicKey { return &l.Key.PublicKey }

// Entry describes what to log.
type Entry struct {
	// Leaf is the signing certificate, DER. Its key must be Signer's.
	Leaf []byte
	// Signer signs the artifact digest: Ed25519 (as Ed25519ph over SHA-512,
	// which is what Rekor accepts for an Ed25519 hashedrekord) or ECDSA
	// (over SHA-256).
	Signer crypto.Signer
	// Artifact is what was signed.
	Artifact []byte
	// IntegratedTime is the log's timestamp for the entry.
	IntegratedTime time.Time
	// LogIndex is the entry's global index.
	LogIndex int64
	// BadSignature logs a signature that does not verify, as a log that
	// skipped its own check would.
	BadSignature bool
	// BodyLeaf, when set, is the certificate named in the log entry in
	// place of Leaf (the bundle still carries Leaf).
	BodyLeaf []byte
}

// Bundle returns a Sigstore bundle (v0.3 JSON) for e, logged in l.
func (l *Log) Bundle(e Entry) ([]byte, error) {
	var (
		digest  []byte
		alg     string
		bundleA string
		sig     []byte
		err     error
	)
	switch s := e.Signer.(type) {
	case ed25519.PrivateKey:
		d := sha512.Sum512(e.Artifact)
		digest, alg, bundleA = d[:], "sha512", "SHA2_512"
		sig, err = s.Sign(nil, digest, &ed25519.Options{Hash: crypto.SHA512})
	case *ecdsa.PrivateKey:
		d := sha256.Sum256(e.Artifact)
		digest, alg, bundleA = d[:], "sha256", "SHA2_256"
		sig, err = ecdsa.SignASN1(rand.Reader, s, digest)
	default:
		return nil, fmt.Errorf("rekortest: unsupported signer %T", e.Signer)
	}
	if err != nil {
		return nil, err
	}
	if e.BadSignature {
		sig[len(sig)-1] ^= 0xff
	}
	bodyLeaf := e.Leaf
	if e.BodyLeaf != nil {
		bodyLeaf = e.BodyLeaf
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bodyLeaf})
	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{"hash": map[string]any{"algorithm": alg, "value": hex.EncodeToString(digest)}},
			"signature": map[string]any{
				"content":   base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(certPEM)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	bodyB64 := base64.StdEncoding.EncodeToString(body)

	set, err := l.SignSET(bodyB64, e.IntegratedTime.Unix(), e.LogIndex)
	if err != nil {
		return nil, err
	}

	// A one-leaf tree: the root is the leaf hash and the proof is empty.
	leafHash := sha256.Sum256(append([]byte{0}, body...))
	checkpoint, err := l.Checkpoint(1, leafHash[:])
	if err != nil {
		return nil, err
	}

	b := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(e.Leaf)},
			"tlogEntries": []any{map[string]any{
				"logIndex":          strconv.FormatInt(e.LogIndex, 10),
				"logId":             map[string]any{"keyId": base64.StdEncoding.EncodeToString(l.logID)},
				"kindVersion":       map[string]any{"kind": "hashedrekord", "version": "0.0.1"},
				"integratedTime":    strconv.FormatInt(e.IntegratedTime.Unix(), 10),
				"inclusionPromise":  map[string]any{"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set)},
				"canonicalizedBody": bodyB64,
				"inclusionProof": map[string]any{
					"logIndex":   "0",
					"rootHash":   base64.StdEncoding.EncodeToString(leafHash[:]),
					"treeSize":   "1",
					"hashes":     []any{},
					"checkpoint": map[string]any{"envelope": checkpoint},
				},
			}},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{"algorithm": bundleA, "digest": base64.StdEncoding.EncodeToString(digest)},
			"signature":     base64.StdEncoding.EncodeToString(sig),
		},
	}
	return json.MarshalIndent(b, "", "  ")
}

// SignSET signs a Rekor v1 signed entry timestamp: ECDSA over the
// canonical JSON of {body, integratedTime, logID, logIndex}.
func (l *Log) SignSET(bodyB64 string, integratedTime, logIndex int64) ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"body":           bodyB64,
		"integratedTime": integratedTime,
		"logID":          hex.EncodeToString(l.logID),
		"logIndex":       logIndex,
	})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, l.Key, h[:])
}

// Checkpoint returns a signed-note checkpoint for a tree of size and root.
func (l *Log) Checkpoint(size uint64, root []byte) (string, error) {
	text := fmt.Sprintf("rekortest.invalid - 1\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(root))
	h := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, l.Key, h[:])
	if err != nil {
		return "", err
	}
	line := base64.StdEncoding.EncodeToString(append(append([]byte{}, l.logID[:4]...), sig...))
	return text + "\n— rekortest.invalid " + line + "\n", nil
}
