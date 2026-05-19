package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXDGKeystoreDir_Unset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, set := XDGKeystoreDir()
	if set {
		t.Fatalf("XDG_CONFIG_HOME unset: expected set=false, got set=true (dir=%q)", dir)
	}
	if dir != "" {
		t.Fatalf("XDG_CONFIG_HOME unset: expected dir=\"\", got %q", dir)
	}
}

func TestXDGKeystoreDir_Set(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	dir, set := XDGKeystoreDir()
	if !set {
		t.Fatal("XDG_CONFIG_HOME set: expected set=true, got set=false")
	}
	want := filepath.Join(tmp, "signet")
	if dir != want {
		t.Fatalf("XDG_CONFIG_HOME=%q: expected dir=%q, got %q", tmp, want, dir)
	}
}

// TestXDGRoutesInitAndLoad is the dogfood-grade end-to-end test that
// closes signet-b30dd4. With XDG_CONFIG_HOME set to a fresh tmp dir,
// init writes to that dir AND a subsequent LoadMasterKeySecure /
// GetKeyIDSecure reads from that dir — the OS keyring is bypassed
// entirely.
//
// This was the failing scenario at b30dd4's filing: previously,
// init would write to the keyring regardless of any path hint, and
// LoadMasterKeySecure would always check the keyring first, so an
// "isolated" home was a lie. With XDG support, the env var is the
// hard switch.
func TestXDGRoutesInitAndLoad(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Init: should write master.key under $XDG_CONFIG_HOME/signet/, not
	// the user's keyring.
	if err := InitializeSecure(false); err != nil {
		t.Fatalf("InitializeSecure with XDG_CONFIG_HOME set: %v", err)
	}

	keyPath := filepath.Join(tmp, "signet", "master.key")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected master.key at %s, stat error: %v", keyPath, err)
	}

	// Load: should read from the XDG dir, NOT the OS keyring. If
	// LoadMasterKeySecure still hit the keyring first, this would
	// either succeed against the developer's real key (returning a
	// different KID than the freshly-written one) or fail when no
	// keyring entry exists. Both are bugs.
	signer, err := LoadMasterKeySecure()
	if err != nil {
		t.Fatalf("LoadMasterKeySecure with XDG_CONFIG_HOME set: %v", err)
	}
	signer.Destroy()

	// GetKeyIDSecure should also be XDG-aware. Its return value must
	// match GetKeyIDInsecure against the same path.
	xdgKID, err := GetKeyIDInsecure(filepath.Join(tmp, "signet"))
	if err != nil {
		t.Fatalf("GetKeyIDInsecure against XDG dir: %v", err)
	}
	secureKID, err := GetKeyIDSecure()
	if err != nil {
		t.Fatalf("GetKeyIDSecure with XDG_CONFIG_HOME set: %v", err)
	}
	if xdgKID != secureKID {
		t.Fatalf("GetKeyIDSecure (XDG-routed) returned %q but GetKeyIDInsecure (direct) returned %q — XDG routing is leaking to keyring", secureKID, xdgKID)
	}
}

// TestXDGForceReinit confirms --force re-initialization works through
// the XDG path (the keyring's existing-key-check is correctly skipped
// when XDG is set).
func TestXDGForceReinit(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	if err := InitializeSecure(false); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if err := InitializeSecure(false); err == nil {
		t.Fatal("second init without --force should fail (key exists)")
	}
	if err := InitializeSecure(true); err != nil {
		t.Fatalf("second init with --force should succeed: %v", err)
	}
}
