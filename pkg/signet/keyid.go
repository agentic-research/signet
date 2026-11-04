package signet

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// issuerKeyIDBytes is how many leading bytes of the SPKI hash a key id
// keeps: 16 bytes, 32 hex characters, the 128-bit kid of ADR-012.
const issuerKeyIDBytes = 16

// IssuerKeyID returns the id under which a CA bundle lists the issuing key
// pub, in the form the bundle's `keyId`, `prevKeyId` and `keys` map use:
//
//	kid = lowercasehex( SHA-256( canonical SPKI DER )[:16] )   // 128-bit, 32 hex
//
// This is the canonical key id of ADR-012 (docs/design/012-canonical-key-id.md),
// the value notme's keyIdFromSpki publishes for an authority key, pinned by
// the conformance vector: the Ed25519 public key 00..1f yields
// 9408457aefd071cec127c1f985399308. sigid.CanonicalKeyID is this function.
//
// It is the one derivation shared by every party to the revocation check: a
// token issuer stores it in Token.KeyID (see WithIssuerKey), a bundle
// publisher keys the bundle with it, and revocation.CABundleChecker compares
// the two. Deriving the id anywhere else is how issuer and checker drift.
//
// Canonicalize-then-hash: the DER is re-encoded from the parsed key, so two
// valid SPKI encodings of one key yield one id.
func IssuerKeyID(pub crypto.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("issuer key id: nil public key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("issuer key id: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:issuerKeyIDBytes]), nil
}

// TokenOption sets an optional field of a token built by NewToken.
type TokenOption func(*Token) error

// WithIssuerKey records the id of the issuing CA key, pub, in Token.KeyID,
// derived by IssuerKeyID. A token checked by revocation.CABundleChecker
// needs it: the checker refuses a token whose key id is missing or not in
// the issuer's bundle.
func WithIssuerKey(pub crypto.PublicKey) TokenOption {
	return func(t *Token) error {
		kid, err := IssuerKeyID(pub)
		if err != nil {
			return err
		}
		t.KeyID = []byte(kid)
		return nil
	}
}
