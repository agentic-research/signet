package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"net/http"
	"strings"
	"testing"

	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/require"
)

func TestNewSignetKMS_SessionSignsWithoutLocalKeystore(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	session, err := startKMSSession(keys.NewEd25519Signer(privateKey))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	t.Setenv(sessionSocketEnv, session.SocketPath())
	t.Setenv(sessionTokenEnv, session.Token())

	// Sigstore selects the sigstore-kms-signet executable from the URI scheme,
	// then passes only the key reference to the plugin process.
	kms, err := NewSignetKMS("session")
	require.NoError(t, err)
	t.Cleanup(kms.Destroy)

	signature, err := kms.SignMessage(strings.NewReader("artifact digest"))
	require.NoError(t, err)
	require.NoError(t, kms.VerifySignature(
		bytes.NewReader(signature),
		strings.NewReader("artifact digest"),
	))
}

func TestKMSSession_RejectsMissingBearerToken(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	session, err := startKMSSession(keys.NewEd25519Signer(privateKey))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	client := newSessionHTTPClient(session.SocketPath())
	request, err := http.NewRequest(http.MethodGet, sessionBaseURL+sessionPublicKeyPath, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })

	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
}

func TestNewSignetKMS_SessionRequiresSocketEnvironment(t *testing.T) {
	t.Setenv(sessionSocketEnv, "")
	t.Setenv(sessionTokenEnv, "")

	_, err := NewSignetKMS("signet://session")
	require.ErrorContains(t, err, sessionSocketEnv)
}

func TestSignetKMS_SignsDigestOptionUsedByCryptoSigner(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	session, err := startKMSSession(keys.NewEd25519Signer(privateKey))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	t.Setenv(sessionSocketEnv, session.SocketPath())
	t.Setenv(sessionTokenEnv, session.Token())

	kms, err := NewSignetKMS("session")
	require.NoError(t, err)
	t.Cleanup(kms.Destroy)

	payload := []byte("bundle payload passed as a digest option")
	signatureBytes, err := kms.SignMessage(
		strings.NewReader(""),
		options.WithDigest(payload),
		options.WithCryptoSignerOpts(crypto.Hash(0)),
	)
	require.NoError(t, err)
	publicKey := kms.pubKey.(ed25519.PublicKey)
	require.True(t, ed25519.Verify(publicKey, payload, signatureBytes))
}

func TestSignetKMS_SignsSHA512DigestAsEd25519ph(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	session, err := startKMSSession(keys.NewEd25519Signer(privateKey))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	t.Setenv(sessionSocketEnv, session.SocketPath())
	t.Setenv(sessionTokenEnv, session.Token())

	kms, err := NewSignetKMS("session")
	require.NoError(t, err)
	t.Cleanup(kms.Destroy)

	digest := sha512.Sum512([]byte("Sigstore bundle payload"))
	signatureBytes, err := kms.SignMessage(
		strings.NewReader(""),
		options.WithDigest(digest[:]),
	)
	require.NoError(t, err)
	publicKey := kms.pubKey.(ed25519.PublicKey)
	require.NoError(t, ed25519.VerifyWithOptions(
		publicKey,
		digest[:],
		signatureBytes,
		&ed25519.Options{Hash: crypto.SHA512},
	))
	require.False(t, ed25519.Verify(publicKey, digest[:], signatureBytes))
}
