package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/keys"
	"github.com/stretchr/testify/require"
)

const (
	testCTLogURL   = "https://ct.example/logs/notme"
	testCTLogStart = "2026-07-01T00:00:00Z"
)

// testCTLogKey returns a fresh P-256 key as notme pins it in CT_LOG_KEY:
// base64 of the SPKI DER.
func testCTLogKey(t *testing.T) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der), der
}

func TestParseCTLogConfig_UnsetIsNil(t *testing.T) {
	config, err := parseCTLogConfig("", "", "")
	require.NoError(t, err)
	require.Nil(t, config)

	// Whitespace-only values are unset, not a half-configured log: an Action
	// input left blank arrives as an empty or whitespace string.
	config, err = parseCTLogConfig("  ", "\n", "\t")
	require.NoError(t, err)
	require.Nil(t, config)
}

func TestParseCTLogConfig_Complete(t *testing.T) {
	keyB64, der := testCTLogKey(t)
	config, err := parseCTLogConfig(testCTLogURL, keyB64, testCTLogStart)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Equal(t, testCTLogURL, config.URL)
	require.Equal(t, der, config.PublicKeyDER)
	require.True(t, config.StartTime.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)))
}

func TestParseCTLogConfig_HalfConfiguredRefuses(t *testing.T) {
	keyB64, _ := testCTLogKey(t)
	for _, tc := range []struct {
		name, url, key, start string
	}{
		{"url only", testCTLogURL, "", ""},
		{"key only", "", keyB64, ""},
		{"start-time only", "", "", testCTLogStart},
		{"url and key, no start-time", testCTLogURL, keyB64, ""},
		{"url and start-time, no key", testCTLogURL, "", testCTLogStart},
		{"key and start-time, no url", "", keyB64, testCTLogStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := parseCTLogConfig(tc.url, tc.key, tc.start)
			require.Error(t, err)
			require.Nil(t, config)
			require.ErrorContains(t, err, "CT log is half-configured")
		})
	}
}

func TestParseCTLogConfig_RejectsMalformedValues(t *testing.T) {
	keyB64, _ := testCTLogKey(t)
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	require.NoError(t, err)

	for _, tc := range []struct {
		name, url, key, start, want string
	}{
		{"plain http url", "http://ct.example/logs/notme", keyB64, testCTLogStart, "https"},
		{"url without host", "https:///logs/notme", keyB64, testCTLogStart, "host"},
		{"url with comma", "https://ct.example/logs,notme", keyB64, testCTLogStart, "comma"},
		{"key not base64", testCTLogURL, "not base64!", testCTLogStart, "base64"},
		{"key not SPKI", testCTLogURL, base64.StdEncoding.EncodeToString([]byte("junk")), testCTLogStart, "SPKI"},
		{"ed25519 key", testCTLogURL, base64.StdEncoding.EncodeToString(edDER), testCTLogStart, "P-256"},
		{"p384 key", testCTLogURL, base64.StdEncoding.EncodeToString(p384DER), testCTLogStart, "P-256"},
		{"start-time not RFC 3339", testCTLogURL, keyB64, "2026-07-01", "RFC 3339"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := parseCTLogConfig(tc.url, tc.key, tc.start)
			require.Error(t, err)
			require.Nil(t, config)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSignArtifactsWithSession_CTLogConfiguredRequiresSCT(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "release.tar.zst")
	require.NoError(t, os.WriteFile(artifact, []byte("release bytes"), 0o600))

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
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

	keyB64, der := testCTLogKey(t)
	ctLog, err := parseCTLogConfig(testCTLogURL, keyB64, testCTLogStart)
	require.NoError(t, err)

	outputs := artifactOutputPaths(artifact)
	var calls [][]string
	runner := func(_ context.Context, _ []string, _ io.Writer, _ io.Writer, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "trusted-root":
			require.Len(t, args, 8)
			// The log key reaches cosign as a PEM file holding exactly the
			// pinned SPKI DER.
			ctfePrefix := "--ctfe=url=" + testCTLogURL + ",public-key="
			require.True(t, strings.HasPrefix(args[5], ctfePrefix), args[5])
			keyPath, startTime, found := strings.Cut(args[5][len(ctfePrefix):], ",start-time=")
			require.True(t, found, args[5])
			require.Equal(t, testCTLogStart, startTime)
			keyPEM, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			block, rest := pem.Decode(keyPEM)
			require.NotNil(t, block)
			require.Empty(t, rest)
			require.Equal(t, "PUBLIC KEY", block.Type)
			require.Equal(t, der, block.Bytes)
			require.NoError(t, os.WriteFile(args[7], []byte("trusted root"), 0o600))
			return nil
		case "sign-blob":
			require.NoError(t, os.WriteFile(outputs.Bundle, []byte("bundle"), 0o600))
			return nil
		}
		return errors.New("verification failed")
	}

	err = signArtifactsWithSession(t.Context(), enrolled, ctLog, []string{artifact}, runner, io.Discard, io.Discard)
	require.ErrorContains(t, err, "verification failed")
	require.Len(t, calls, 3)

	trustedRootPath := calls[0][7]
	require.Equal(t, []string{
		"trusted-root", "create",
		"--with-default-services",
		// Kept with a log configured: it strips only the public Sigstore CT
		// logs, so notme's log is the ONLY one whose SCT satisfies verify.
		"--no-default-ctfe",
		"--fulcio=url=https://cloister.example/identity,certificate-chain=" + filepath.Join(filepath.Dir(trustedRootPath), "authority-ca.pem"),
		calls[0][5],
		"--out", trustedRootPath,
	}, calls[0])

	// verify-blob must NOT ignore SCTs once a log is configured: that flag is
	// what decides whether an SCT is required, not the trusted root.
	require.NotContains(t, calls[2], "--insecure-ignore-sct")
	require.Equal(t, []string{
		"verify-blob",
		"--trusted-root", trustedRootPath,
		"--certificate-identity", enrolled.Identity,
		"--certificate-oidc-issuer-regexp", "^$",
		"--allow-certificate-chain",
		"--bundle", outputs.Bundle,
		artifact,
	}, calls[2])

	// The temporary log key is removed with the trusted root.
	_, err = os.Stat(filepath.Dir(trustedRootPath))
	require.True(t, os.IsNotExist(err), "temporary trusted-root directory must be removed")
}

func TestCosignVerifyBlobArgs_SCTRequirementFollowsConfig(t *testing.T) {
	outputs := artifactOutputPaths("a")
	require.Contains(t, cosignVerifyBlobArgs("a", outputs, "root.json", "id", false), "--insecure-ignore-sct")
	require.NotContains(t, cosignVerifyBlobArgs("a", outputs, "root.json", "id", true), "--insecure-ignore-sct")
}

func TestRunSignArtifactCommand_HalfConfiguredRefusesBeforeEnrollment(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(artifact, []byte("bytes"), 0o600))
	// No GitHub OIDC environment: if enrollment were reached it would fail
	// with a different error, so this proves the refusal comes first.
	t.Setenv(githubOIDCRequestURLEnv, "")
	t.Setenv(githubOIDCRequestTokenEnv, "")

	err := runSignArtifactCommand(t.Context(), []string{"--ct-log-url", testCTLogURL, artifact}, io.Discard, io.Discard)
	require.ErrorContains(t, err, "CT log is half-configured")
}

// TestCreateCosignTrustedRoot_CTLogCosignIntegration runs the real
// `cosign trusted-root create` and checks the JSON it writes. It needs cosign
// on PATH and network access to the Sigstore TUF repository
// (--with-default-services), so it skips without cosign and under -short.
func TestCreateCosignTrustedRoot_CTLogCosignIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("needs cosign and the Sigstore TUF repository")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign is not on PATH")
	}

	caPEM := testSelfSignedCAPEM(t)
	enrolled := &enrollment{AuthorityURL: "https://cloister.example/identity", CABundlePEM: caPEM}
	keyB64, der := testCTLogKey(t)
	ctLog, err := parseCTLogConfig(testCTLogURL, keyB64, testCTLogStart)
	require.NoError(t, err)

	type trustedRoot struct {
		CTLogs []struct {
			BaseURL   string `json:"baseUrl"`
			PublicKey struct {
				RawBytes []byte `json:"rawBytes"`
				ValidFor struct {
					Start string `json:"start"`
				} `json:"validFor"`
			} `json:"publicKey"`
			LogID struct {
				KeyID []byte `json:"keyId"`
			} `json:"logId"`
		} `json:"ctlogs"`
	}
	create := func(ctLog *ctLogConfig) trustedRoot {
		t.Helper()
		var stderr strings.Builder
		path, cleanup, err := createCosignTrustedRoot(t.Context(), enrolled, ctLog, os.Environ(), runCosign, io.Discard, &stderr)
		require.NoError(t, err, stderr.String())
		t.Cleanup(cleanup)
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		var root trustedRoot
		require.NoError(t, json.Unmarshal(raw, &root))
		return root
	}

	// Unset: today's trusted root carries no CT log at all.
	require.Empty(t, create(nil).CTLogs)

	// Set: exactly notme's log, keyed by the pinned SPKI, with log id
	// SHA-256(SPKI) — the value notme pins as CT_LOG_ID.
	root := create(ctLog)
	require.Len(t, root.CTLogs, 1)
	logEntry := root.CTLogs[0]
	require.Equal(t, testCTLogURL, logEntry.BaseURL)
	require.Equal(t, der, logEntry.PublicKey.RawBytes)
	require.Equal(t, testCTLogStart, logEntry.PublicKey.ValidFor.Start)
	sum := sha256.Sum256(der)
	require.Equal(t, sum[:], logEntry.LogID.KeyID)
}

func testSelfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestSignArtifactCommand_CTLogFlagsReachCosign follows the three flags from
// the command line to cosign's argv, so a config that is parsed and then
// dropped before signing is caught.
func TestSignArtifactCommand_CTLogFlagsReachCosign(t *testing.T) {
	keyB64, _ := testCTLogKey(t)
	for _, tc := range []struct {
		name       string
		flags      []string
		requireSCT bool
	}{
		{"unset", nil, false},
		{"set", []string{
			"--ct-log-url", testCTLogURL,
			"--ct-log-public-key", keyB64,
			"--ct-log-start-time", testCTLogStart,
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := filepath.Join(t.TempDir(), "artifact.bin")
			require.NoError(t, os.WriteFile(artifact, []byte("bytes"), 0o600))
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			enroll := func(_ context.Context, cfg enrollConfig) (*enrollment, error) {
				return &enrollment{
					Signer:                keys.NewEd25519Signer(privateKey),
					SigningCertificatePEM: []byte("leaf\n"),
					CABundlePEM:           []byte("ca\n"),
					PublicKeyPEM:          []byte("pub\n"),
					AuthorityURL:          cfg.AuthorityURL,
					Identity:              "wimse://notme.bot/principal/x",
					ExpiresAt:             time.Now().Add(5 * time.Minute),
				}, nil
			}
			var calls [][]string
			runner := func(_ context.Context, _ []string, _ io.Writer, _ io.Writer, args ...string) error {
				calls = append(calls, append([]string(nil), args...))
				switch args[0] {
				case "trusted-root":
					return os.WriteFile(args[len(args)-1], []byte("root"), 0o600)
				case "sign-blob":
					return os.WriteFile(artifactOutputPaths(artifact).Bundle, []byte("bundle"), 0o600)
				}
				return nil
			}

			args := append(append([]string(nil), tc.flags...), artifact)
			require.NoError(t, signArtifactCommand(t.Context(), args, io.Discard, io.Discard, enroll, runner))
			require.Len(t, calls, 3)

			hasCTFE := false
			for _, arg := range calls[0] {
				if strings.HasPrefix(arg, "--ctfe=") {
					hasCTFE = true
				}
			}
			require.Equal(t, tc.requireSCT, hasCTFE, calls[0])
			require.Contains(t, calls[0], "--no-default-ctfe")
			require.Equal(t, !tc.requireSCT, slices.Contains(calls[2], "--insecure-ignore-sct"), calls[2])
		})
	}
}
