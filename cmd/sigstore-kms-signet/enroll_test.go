package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testOIDCToken = "header.payload.signature"

type enrollmentFixture struct {
	authorityURL string
	client       *http.Client
	oidcURL      string
}

func TestEnrollGitHubSession_ImplementsNotmeActionProtocol(t *testing.T) {
	fixture := newEnrollmentFixture(t, false)
	t.Setenv(githubOIDCRequestURLEnv, fixture.oidcURL)
	t.Setenv(githubOIDCRequestTokenEnv, "request-capability")

	enrolled, err := enrollGitHubSession(t.Context(), enrollConfig{
		AuthorityURL: fixture.authorityURL,
		Audience:     "notme.bot",
		HTTPClient:   fixture.client,
	})
	require.NoError(t, err)
	t.Cleanup(enrolled.Destroy)

	require.Equal(t, "wimse://cluster.example/gha/agentic-research/signet", enrolled.Identity)
	require.WithinDuration(t, time.Now().Add(5*time.Minute), enrolled.ExpiresAt, 10*time.Second)
	require.Contains(t, string(enrolled.SigningCertificatePEM), "BEGIN CERTIFICATE")
	require.Contains(t, string(enrolled.CABundlePEM), "BEGIN CERTIFICATE")

	signature, err := enrolled.Signer.Sign(rand.Reader, []byte("release artifact"), crypto.Hash(0))
	require.NoError(t, err)
	publicKey := enrolled.Signer.Public().(ed25519.PublicKey)
	require.True(t, ed25519.Verify(publicKey, []byte("release artifact"), signature))
}

func TestEnrollGitHubSession_RejectsCertificateForDifferentSigningKey(t *testing.T) {
	fixture := newEnrollmentFixture(t, true)
	t.Setenv(githubOIDCRequestURLEnv, fixture.oidcURL)
	t.Setenv(githubOIDCRequestTokenEnv, "request-capability")

	_, err := enrollGitHubSession(t.Context(), enrollConfig{
		AuthorityURL: fixture.authorityURL,
		Audience:     "notme.bot",
		HTTPClient:   fixture.client,
	})
	require.ErrorContains(t, err, "does not match ephemeral signing key")
}

func TestFetchGitHubOIDCToken_RequiresAmbientCredentials(t *testing.T) {
	t.Setenv(githubOIDCRequestURLEnv, "")
	t.Setenv(githubOIDCRequestTokenEnv, "")

	_, err := fetchGitHubOIDCToken(t.Context(), http.DefaultClient, os.Getenv, "notme.bot")
	require.ErrorContains(t, err, "id-token: write")
}

func newEnrollmentFixture(t *testing.T, mismatchedLeaf bool) enrollmentFixture {
	t.Helper()

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cluster-notme-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	oidcServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodGet, request.Method)
		require.Equal(t, "notme.bot", request.URL.Query().Get("audience"))
		require.Equal(t, "Bearer request-capability", request.Header.Get("Authorization"))
		_ = json.NewEncoder(response).Encode(map[string]string{"value": testOIDCToken})
	}))
	t.Cleanup(oidcServer.Close)

	authorityMux := http.NewServeMux()
	authorityMux.HandleFunc("/identity/cert/gha", func(response http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodPost, request.Method)
		require.Equal(t, "Bearer "+testOIDCToken, request.Header.Get("Authorization"))

		var body struct {
			PublicKeys struct {
				MTLS    string `json:"mtls"`
				Signing string `json:"signing"`
			} `json:"public_keys"`
			Proofs struct {
				MTLS    string `json:"mtls"`
				Signing string `json:"signing"`
			} `json:"proofs"`
		}
		require.NoError(t, json.NewDecoder(request.Body).Decode(&body))

		mtlsDER := decodePublicKeyPEM(t, body.PublicKeys.MTLS)
		signingDER := decodePublicKeyPEM(t, body.PublicKeys.Signing)
		mtlsParsed, err := x509.ParsePKIXPublicKey(mtlsDER)
		require.NoError(t, err)
		mtlsPublic, ok := mtlsParsed.(*ecdsa.PublicKey)
		require.True(t, ok)
		signingParsed, err := x509.ParsePKIXPublicKey(signingDER)
		require.NoError(t, err)
		signingPublic, ok := signingParsed.(ed25519.PublicKey)
		require.True(t, ok)

		oidcDigest := sha256.Sum256([]byte(testOIDCToken))
		bindingInput := append(append(append([]byte{}, mtlsDER...), signingDER...), oidcDigest[:]...)
		binding := sha256.Sum256(bindingInput)
		mtlsProof, err := base64.RawURLEncoding.DecodeString(body.Proofs.MTLS)
		require.NoError(t, err)
		require.Len(t, mtlsProof, 64)
		r := new(big.Int).SetBytes(mtlsProof[:32])
		s := new(big.Int).SetBytes(mtlsProof[32:])
		require.True(t, ecdsa.Verify(mtlsPublic, binding[:], r, s))
		signingProof, err := base64.RawURLEncoding.DecodeString(body.Proofs.Signing)
		require.NoError(t, err)
		require.True(t, ed25519.Verify(signingPublic, binding[:], signingProof))

		leafPublic := ed25519.PublicKey(signingPublic)
		if mismatchedLeaf {
			leafPublic, _, err = ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
		}
		identityURL, err := url.Parse("wimse://cluster.example/gha/agentic-research/signet")
		require.NoError(t, err)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "repo:agentic-research/signet:ref:refs/heads/main"},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(5 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			URIs:         []*url.URL{identityURL},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, leafPublic, caPrivate)
		require.NoError(t, err)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		response.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(response).Encode(map[string]any{
			"certificates": map[string]string{"mtls": string(leafPEM), "signing": string(leafPEM)},
			"identity":     identityURL.String(),
			"scopes":       []string{"bridgeCert"},
			"expires_at":   leafTemplate.NotAfter.Unix(),
			"binding":      base64.RawURLEncoding.EncodeToString(binding[:]),
			"authority":    map[string]any{"epoch": 1, "key_id": "test-ca"},
			"claims":       map[string]string{"repository": "agentic-research/signet"},
		}))
	})
	authorityMux.HandleFunc("/identity/.well-known/ca-bundle.pem", func(response http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodGet, request.Method)
		response.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = response.Write(caPEM)
	})
	authorityServer := httptest.NewServer(authorityMux)
	t.Cleanup(authorityServer.Close)

	return enrollmentFixture{
		authorityURL: authorityServer.URL + "/identity",
		client:       authorityServer.Client(),
		oidcURL:      oidcServer.URL + "?existing=1",
	}
}

func decodePublicKeyPEM(t *testing.T, value string) []byte {
	t.Helper()
	block, rest := pem.Decode([]byte(value))
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)
	require.Empty(t, strings.TrimSpace(string(rest)))
	return block.Bytes
}
