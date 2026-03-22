package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	keyPEM, pubHex, err := generateKey()
	require.NoError(t, err)
	require.NotNil(t, keyPEM)
	require.NotEmpty(t, pubHex)

	// Verify PEM is valid and contains an Ed25519 seed
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block, "returned PEM should be decodable")
	assert.Equal(t, "ED25519 PRIVATE KEY", block.Type)
	assert.Equal(t, ed25519.SeedSize, len(block.Bytes), "PEM should contain a 32-byte seed")

	// Verify public key hex is 64 chars (32 bytes hex-encoded)
	assert.Len(t, pubHex, 64)

	// Verify the public key corresponds to the seed
	priv := ed25519.NewKeyFromSeed(block.Bytes)
	expectedPubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	assert.Equal(t, expectedPubHex, pubHex)
}

func TestGenerateKey_Uniqueness(t *testing.T) {
	_, pub1, err := generateKey()
	require.NoError(t, err)
	_, pub2, err := generateKey()
	require.NoError(t, err)
	assert.NotEqual(t, pub1, pub2, "generated keys must be unique")
}

func TestLoadExistingKey_SignetFormat(t *testing.T) {
	// Create a key in signet's raw seed format
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	expectedPub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	keyPath := filepath.Join(t.TempDir(), "master.key")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	data, pubHex, err := loadExistingKey(keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedPub, pubHex)
	assert.Equal(t, keyPEM, data, "should return original PEM data for upload")
}

func TestLoadExistingKey_PKCS8Format(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	expectedPub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	keyPath := filepath.Join(t.TempDir(), "master.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	data, pubHex, err := loadExistingKey(keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedPub, pubHex)
	assert.Equal(t, keyPEM, data)
}

func TestLoadExistingKey_RejectsInsecurePermissions(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	keyPath := filepath.Join(t.TempDir(), "master.key")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o644))

	_, _, err = loadExistingKey(keyPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure key file permissions")
}

func TestLoadExistingKey_RejectsWorldReadable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	keyPath := filepath.Join(t.TempDir(), "master.key")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o604))

	_, _, err = loadExistingKey(keyPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure key file permissions")
}

func TestLoadExistingKey_RejectsInvalidPEM(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "garbage.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not PEM data"), 0o600))

	_, _, err := loadExistingKey(keyPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
}

func TestLoadExistingKey_RejectsUnsupportedPEMType(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})
	keyPath := filepath.Join(t.TempDir(), "rsa.key")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	_, _, err := loadExistingKey(keyPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM type")
}

func TestLoadExistingKey_RejectsInvalidSeedSize(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte("too short"),
	})
	keyPath := filepath.Join(t.TempDir(), "bad.key")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	_, _, err := loadExistingKey(keyPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid seed size")
}

func TestLoadExistingKey_FileNotFound(t *testing.T) {
	_, _, err := loadExistingKey("/tmp/nonexistent-signet-key.pem")
	require.Error(t, err)
}

func TestResolveRepo_ValidFormat(t *testing.T) {
	setupResignRepo = "owner/repo"
	defer func() { setupResignRepo = "" }()

	repo, err := resolveRepo()
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", repo)
}

func TestResolveRepo_ValidWithDotsAndHyphens(t *testing.T) {
	setupResignRepo = "agentic-research/go-cms"
	defer func() { setupResignRepo = "" }()

	repo, err := resolveRepo()
	require.NoError(t, err)
	assert.Equal(t, "agentic-research/go-cms", repo)
}

func TestResolveRepo_RejectsPathTraversal(t *testing.T) {
	tests := []string{
		"owner/repo/../../../admin",
		"../evil/path",
		"owner/repo/extra",
		"/",
		"owner/",
		"/repo",
	}
	for _, input := range tests {
		setupResignRepo = input
		_, err := resolveRepo()
		assert.Error(t, err, "should reject %q", input)
	}
	setupResignRepo = ""
}

func TestResolveRepo_RejectsEmptyParts(t *testing.T) {
	setupResignRepo = "/repo"
	defer func() { setupResignRepo = "" }()

	_, err := resolveRepo()
	require.Error(t, err)
}

func TestRepoPattern(t *testing.T) {
	valid := []string{
		"owner/repo",
		"agentic-research/signet",
		"my_org/my.repo",
		"CAPS/REPO",
		"a/b",
	}
	for _, r := range valid {
		assert.True(t, repoPattern.MatchString(r), "should accept %q", r)
	}

	invalid := []string{
		"owner/repo/extra",
		"owner/repo/../hack",
		"single",
		"",
		"owner/",
		"/repo",
		"owner/repo name",
		"owner/repo;cmd",
	}
	for _, r := range invalid {
		assert.False(t, repoPattern.MatchString(r), "should reject %q", r)
	}
}

func TestSetupResignCmd_IsRegistered(t *testing.T) {
	// Verify setup-resign is a subcommand of authority
	found := false
	for _, cmd := range authorityCmd.Commands() {
		if cmd.Use == "setup-resign" {
			found = true
			break
		}
	}
	assert.True(t, found, "setup-resign must be registered as a subcommand of authority")
}

func TestSetupResignCmd_RequiresGh(t *testing.T) {
	// Temporarily override PATH to exclude gh
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // empty dir, no gh

	err := runSetupResign(setupResignCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub CLI (gh) is required")

	os.Setenv("PATH", origPath)
}
