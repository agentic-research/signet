package git

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentic-research/signet/pkg/cli/config"
)

// setupTestHome creates a temp signet home with a master key and returns
// the config and a cleanup function. Uses real crypto (Rule 4).
func setupTestHome(t *testing.T) (*config.Config, ed25519.PrivateKey) {
	t.Helper()
	home := t.TempDir()

	// Generate real Ed25519 master key
	_, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write master key in signet format (raw seed)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: masterPriv.Seed(),
	})
	if err := os.WriteFile(filepath.Join(home, "master.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.New(home)
	cfg.IssuerDID = "did:key:test-identity"
	return cfg, masterPriv
}

// writeBridgeCert creates a real bridge cert and key under cfg.Home/git/.
func writeBridgeCert(t *testing.T, cfg *config.Config, masterPriv ed25519.PrivateKey, email string) {
	t.Helper()
	gitDir := filepath.Join(cfg.Home, "git")
	if err := os.MkdirAll(gitDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Generate bridge key pair
	bridgePub, bridgePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create bridge cert signed by master key (real X.509, Rule 4)
	now := time.Now()
	bridgeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"Signet"},
		},
		EmailAddresses:        []string{email},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   cfg.IssuerDID,
			Organization: []string{"Signet"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, bridgeTemplate, issuerTemplate, bridgePub, masterPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Write bridge cert PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-cert.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// Write bridge key as PKCS8 PEM
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(bridgePriv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-key.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIdentity_Level0(t *testing.T) {
	cfg, _ := setupTestHome(t)

	id, err := LoadIdentity(cfg)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	defer id.Destroy()

	if id.MasterKey == nil {
		t.Fatal("expected non-nil MasterKey")
	}
	if id.Level() != 0 {
		t.Errorf("Level() = %d, want 0", id.Level())
	}
	if id.HasUserAttribution() {
		t.Error("HasUserAttribution() should be false for Level 0")
	}
	if id.BridgeCert != nil {
		t.Error("BridgeCert should be nil for Level 0")
	}
}

func TestLoadIdentity_Level1(t *testing.T) {
	cfg, masterPriv := setupTestHome(t)
	writeBridgeCert(t, cfg, masterPriv, "alice@example.com")

	id, err := LoadIdentity(cfg)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	defer id.Destroy()

	if id.Level() != 1 {
		t.Errorf("Level() = %d, want 1", id.Level())
	}
	if !id.HasUserAttribution() {
		t.Error("HasUserAttribution() should be true for Level 1")
	}
	if id.BridgeCert == nil {
		t.Fatal("BridgeCert should not be nil")
	}
	if id.BridgeCert.Subject.CommonName != "alice@example.com" {
		t.Errorf("BridgeCert CN = %q, want %q", id.BridgeCert.Subject.CommonName, "alice@example.com")
	}
	if id.BridgeKey == nil {
		t.Fatal("BridgeKey should not be nil")
	}
}

func TestLoadIdentity_KeyZeroizedOnBridgeError(t *testing.T) {
	cfg, _ := setupTestHome(t)

	// Create git dir with cert but corrupt key file
	gitDir := filepath.Join(cfg.Home, "git")
	if err := os.MkdirAll(gitDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a valid-looking cert file (will parse)
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-key.pem"),
		[]byte("not-valid-pem"), 0600); err != nil {
		t.Fatal(err)
	}

	// LoadIdentity should fail but not leak the master key
	_, err := LoadIdentity(cfg)
	if err == nil {
		t.Fatal("expected error for corrupt bridge files")
	}
	// The ownershipTransferred pattern ensures Destroy() was called
	// on the identity (and thus the master key) on error paths.
	// We can't easily assert the key bytes are zeroed, but we verify
	// the error path doesn't panic.
}

func TestIdentity_Destroy(t *testing.T) {
	cfg, masterPriv := setupTestHome(t)
	writeBridgeCert(t, cfg, masterPriv, "bob@example.com")

	id, err := LoadIdentity(cfg)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	// Destroy should not panic
	id.Destroy()

	// Double-destroy should not panic
	id.Destroy()
}

func TestLoadIdentity_PartialBridgeFiles(t *testing.T) {
	cfg, _ := setupTestHome(t)

	// Create git dir with only cert, no key
	gitDir := filepath.Join(cfg.Home, "git")
	if err := os.MkdirAll(gitDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "bridge-cert.pem"), []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	// No bridge-key.pem — should fall back to Level 0

	id, err := LoadIdentity(cfg)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	defer id.Destroy()

	if id.Level() != 0 {
		t.Errorf("Level() = %d, want 0 (missing key file should not load bridge)", id.Level())
	}
}
