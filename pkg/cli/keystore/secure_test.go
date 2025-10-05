package keystore

import (
	"crypto/ed25519"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestSecureKeystore(t *testing.T) {
	// Use mock keyring for testing
	keyring.MockInit()

	// Clean up any existing test keys
	_ = keyring.Delete(ServiceName, MasterKeyItem)

	t.Run("Initialize", func(t *testing.T) {
		err := InitializeSecure()
		if err != nil {
			t.Fatalf("InitializeSecure failed: %v", err)
		}

		// Should fail if key already exists
		err = InitializeSecure()
		if err == nil {
			t.Fatal("Expected error when initializing twice")
		}
	})

	t.Run("LoadMasterKey", func(t *testing.T) {
		signer, err := LoadMasterKeySecure()
		if err != nil {
			t.Fatalf("LoadMasterKeySecure failed: %v", err)
		}

		if signer == nil {
			t.Fatal("Expected non-nil signer")
		}

		// Verify it's a valid Ed25519 signer
		pub, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("Public key is not ed25519.PublicKey")
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Errorf("Invalid public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
		}
	})

	t.Run("GetKeyID", func(t *testing.T) {
		keyID, err := GetKeyIDSecure()
		if err != nil {
			t.Fatalf("GetKeyIDSecure failed: %v", err)
		}

		if len(keyID) != ed25519.PublicKeySize*2 { // hex encoding doubles the length
			t.Errorf("Invalid key ID length: got %d, want %d", len(keyID), ed25519.PublicKeySize*2)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := DeleteMasterKeySecure()
		if err != nil {
			t.Fatalf("DeleteMasterKeySecure failed: %v", err)
		}

		// Should fail when key doesn't exist
		err = DeleteMasterKeySecure()
		if err == nil {
			t.Fatal("Expected error when deleting non-existent key")
		}
	})

	t.Run("LoadAfterDelete", func(t *testing.T) {
		_, err := LoadMasterKeySecure()
		if err == nil {
			t.Fatal("Expected error when loading deleted key")
		}
	})
}

func TestSecureKeystoreNotFound(t *testing.T) {
	// Use mock keyring for testing
	keyring.MockInit()

	// Ensure no key exists
	_ = keyring.Delete(ServiceName, MasterKeyItem)

	t.Run("LoadNonExistent", func(t *testing.T) {
		_, err := LoadMasterKeySecure()
		if err == nil {
			t.Fatal("Expected error when loading non-existent key")
		}
	})

	t.Run("GetKeyIDNonExistent", func(t *testing.T) {
		_, err := GetKeyIDSecure()
		if err == nil {
			t.Fatal("Expected error when getting ID of non-existent key")
		}
	})
}
