package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentic-research/signet/pkg/cli/keystore"
	"github.com/agentic-research/signet/pkg/crypto/algorithm"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestReproIssue62_MLDSA44_Signing(t *testing.T) {
	// 1. Mock the keyring
	keyring.MockInit()

	// 2. Initialize with ML-DSA-44
	// We can use the InitializeSecure function directly
	err := keystore.InitializeSecure(true, algorithm.MLDSA44)
	require.NoError(t, err, "Failed to initialize keystore with ML-DSA-44")

	// 3. Create a dummy file to sign
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(inputFile, []byte("test data"), 0644)
	require.NoError(t, err)

	// 4. Setup global flags for runSign
	// runSign uses global variables (cobra style)
	signInitFlag = false
	signOutput = filepath.Join(tmpDir, "test.txt.sig")
	signFormat = "cms"
	signAlgorithm = "ml-dsa-44" // This is only used for init, but good to be consistent

	// reset global flags after test
	defer func() {
		signInitFlag = false
		signOutput = ""
		signFormat = "cms"
		signAlgorithm = "ed25519"
	}()

	// 5. Run runSign
	// We expect this to SUCCEED now by switching to raw format
	err = runSign(nil, []string{inputFile})
	require.NoError(t, err)

	// 6. Verify output
	require.FileExists(t, signOutput)

	// Optional: Verify format was switched (though we can't easily check internal state,
	// the success implies it didn't crash on CMS)
}
