package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
	"github.com/stretchr/testify/require"
)

func TestSignArtifactsWithSession_UsesSignetKMSAndVerifiesBundle(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "release.tar.zst")
	require.NoError(t, os.WriteFile(artifact, []byte("release bytes"), 0o600))

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	enrolled := &enrollment{
		Signer:                keys.NewEd25519Signer(privateKey),
		SigningCertificatePEM: []byte("leaf certificate\n"),
		CABundlePEM:           []byte("cluster CA\n"),
		PublicKeyPEM:          []byte("public key\n"),
		AuthorityURL:          "https://cloister.example/identity",
		Identity:              "wimse://cluster.example/gha/agentic-research/signet",
		ExpiresAt:             time.Now().Add(5 * time.Minute),
	}
	t.Cleanup(enrolled.Destroy)
	require.Equal(t, publicKey, enrolled.Signer.Public())

	outputs := artifactOutputPaths(artifact)
	var calls [][]string
	var trustedRootPath string
	runner := func(_ context.Context, env []string, _ io.Writer, _ io.Writer, args ...string) error {
		require.Contains(t, env, sessionSocketEnv+"="+envValue(env, sessionSocketEnv))
		require.NotEmpty(t, envValue(env, sessionSocketEnv))
		require.NotEmpty(t, envValue(env, sessionTokenEnv))
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "trusted-root" {
			require.Len(t, args, 7)
			require.Equal(t, "create", args[1])
			require.Equal(t, "--with-default-services", args[2])
			require.Equal(t, "--no-default-ctfe", args[3])
			fulcioPrefix := "--fulcio=url=https://cloister.example/identity,certificate-chain="
			require.Contains(t, args[4], fulcioPrefix)
			caPath := args[4][len(fulcioPrefix):]
			caPEM, err := os.ReadFile(caPath)
			require.NoError(t, err)
			require.Equal(t, enrolled.CABundlePEM, caPEM)
			require.Equal(t, "--out", args[5])
			trustedRootPath = args[6]
			require.NoError(t, os.WriteFile(trustedRootPath, []byte("trusted root"), 0o600))
			return nil
		}
		if args[0] == "sign-blob" {
			require.NoError(t, os.WriteFile(outputs.Bundle, []byte("bundle"), 0o600))
			return nil
		}
		return errors.New("verification failed")
	}

	err = signArtifactsWithSession(t.Context(), enrolled, []string{artifact}, runner, io.Discard, io.Discard)
	require.ErrorContains(t, err, "verification failed")
	require.Len(t, calls, 3)
	require.Equal(t, []string{
		"trusted-root", "create",
		"--with-default-services",
		"--no-default-ctfe",
		calls[0][4],
		"--out", trustedRootPath,
	}, calls[0])
	require.Equal(t, [][]string{
		{
			"sign-blob", "--yes",
			"--key", "signet://session",
			"--certificate", outputs.Certificate,
			"--certificate-chain", outputs.CABundle,
			"--trusted-root", trustedRootPath,
			"--bundle", outputs.Bundle,
			artifact,
		},
		{
			"verify-blob",
			"--trusted-root", trustedRootPath,
			"--certificate-identity", enrolled.Identity,
			"--certificate-oidc-issuer-regexp", "^$",
			"--insecure-ignore-sct",
			"--bundle", outputs.Bundle,
			artifact,
		},
	}, calls[1:])

	certificate, err := os.ReadFile(outputs.Certificate)
	require.NoError(t, err)
	require.Equal(t, enrolled.SigningCertificatePEM, certificate)
	caBundle, err := os.ReadFile(outputs.CABundle)
	require.NoError(t, err)
	require.Equal(t, enrolled.CABundlePEM, caBundle)
	publicPEM, err := os.ReadFile(outputs.PublicKey)
	require.NoError(t, err)
	require.Equal(t, enrolled.PublicKeyPEM, publicPEM)
}

func TestValidateArtifactPaths_RejectsMissingArtifact(t *testing.T) {
	err := validateArtifactPaths([]string{filepath.Join(t.TempDir(), "missing.tar.zst")})
	require.ErrorContains(t, err, "does not exist")
}

func TestCosignSessionIntegration(t *testing.T) {
	if os.Getenv("SIGNET_COSIGN_INTEGRATION") != "1" {
		t.Skip("set SIGNET_COSIGN_INTEGRATION=1 to exercise the installed cosign binary and transparency service")
	}
	_, err := exec.LookPath("cosign")
	require.NoError(t, err)

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

	dir := t.TempDir()
	plugin := filepath.Join(dir, "sigstore-kms-signet")
	build := exec.Command("go", "build", "-trimpath", "-o", plugin, ".")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Exercise the real Sigstore CLI plugin transport before cosign layers its
	// bundle and certificate behavior on top.
	_, directPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	directSession, err := startKMSSession(keys.NewEd25519Signer(directPrivate))
	require.NoError(t, err)
	t.Setenv(sessionSocketEnv, directSession.SocketPath())
	t.Setenv(sessionTokenEnv, directSession.Token())
	pluginClient, err := cliplugin.LoadSignerVerifier(t.Context(), "signet://session", crypto.Hash(0))
	require.NoError(t, err)
	directPayload := []byte("direct plugin payload")
	directSignature, err := pluginClient.SignMessage(bytes.NewReader(directPayload))
	require.NoError(t, err)
	directPublic, err := pluginClient.PublicKey()
	require.NoError(t, err)
	require.True(t, ed25519.Verify(directPublic.(ed25519.PublicKey), directPayload, directSignature))
	require.NoError(t, directSession.Close())

	artifact := filepath.Join(dir, "artifact.bin")
	require.NoError(t, os.WriteFile(artifact, []byte("cosign session integration"), 0o600))
	var cosignStdout bytes.Buffer
	var cosignStderr bytes.Buffer
	err = signArtifactsWithSession(
		t.Context(),
		enrolled,
		[]string{artifact},
		runCosign,
		&cosignStdout,
		&cosignStderr,
	)
	require.NoError(t, err, "cosign stdout:\n%s\ncosign stderr:\n%s", cosignStdout.String(), cosignStderr.String())

	outputs := artifactOutputPaths(artifact)
	for _, path := range []string{outputs.Bundle, outputs.Certificate, outputs.CABundle, outputs.PublicKey} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Positive(t, info.Size())
	}
}

func envValue(environment []string, name string) string {
	prefix := name + "="
	for _, entry := range environment {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			return entry[len(prefix):]
		}
	}
	return ""
}
