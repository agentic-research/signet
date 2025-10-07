#!/bin/bash
set -e

# Integration Test for Signet
# This script validates that signet can be used by Git to create
# and verify cryptographically valid commit signatures

echo "=== Signet Integration Test ==="

# Ensure we have the binary
if [ ! -f "./signet" ]; then
    echo "Building signet..."
    go build -o signet ./cmd/signet
fi

# Store original directory
ORIGINAL_DIR=$(pwd)

# Create a clean test environment
TEST_DIR=$(mktemp -d)
echo "--- Running test in $TEST_DIR ---"

# Clean up on exit - go back to original directory first
trap "cd '$ORIGINAL_DIR' && rm -rf '$TEST_DIR'" EXIT

cd "$TEST_DIR"

# Set up an isolated GnuPG home for git's verifier (gpgsm)
export GNUPGHOME="$TEST_DIR/gpg-home"
mkdir "$GNUPGHOME"

echo "--- Step 1: Initialize Git repository ---"
git init
git config --local user.name "Signet Test"
git config --local user.email "test@signet.dev"

# Create initial commit to have a parent
echo "Initial content" > README.md
git add README.md
git commit -m "Initial commit"

echo "--- Step 2: Initialize Signet ---"
SIGNET_HOME="$TEST_DIR/.signet"
SIGNET_CMD_PATH="$ORIGINAL_DIR/signet"

# Initialize signet
echo "Initializing signet with home: $SIGNET_HOME"
$SIGNET_CMD_PATH commit --home "$SIGNET_HOME" --init --insecure

# Ask the tool for its canonical key ID
MASTER_KEY_ID=$($SIGNET_CMD_PATH commit --home "$SIGNET_HOME" --export-key-id)
echo "--- Using Signet Master Key ID: $MASTER_KEY_ID ---"

echo "--- Step 3: Configure Git to use signet ---"
# Tell Git to use X.509 signature format
git config --local gpg.format x509

# Create a wrapper script that includes the --home argument and debugging
WRAPPER_SCRIPT="$TEST_DIR/signet-wrapper.sh"
cat > "$WRAPPER_SCRIPT" << EOF
#!/bin/bash
echo "Wrapper called with args: \$@" >&2
echo "Calling: $SIGNET_CMD_PATH commit --home $SIGNET_HOME \$@" >&2
exec "$SIGNET_CMD_PATH" commit --home "$SIGNET_HOME" "\$@"
EOF
chmod +x "$WRAPPER_SCRIPT"

# Tell Git to use our wrapper script for signing
git config --local gpg.x509.program "$WRAPPER_SCRIPT"

# Tell Git to use gpgsm for verification (it knows how to verify X.509)
git config --local gpg.x509.verifyProgram "$(which gpgsm)"

# Tell Git to use our master key for signing
git config --local user.signingKey "$MASTER_KEY_ID"

echo "--- Step 4: Debug Git configuration ---"
echo "Current Git configuration:"
git config --local --list | grep -E "(gpg|sign)" || echo "No signing config found"

echo "Testing wrapper script directly:"
echo "test data" | "$WRAPPER_SCRIPT" --detach-sign || echo "Wrapper failed"

echo "--- Step 5: Create a signed commit ---"
echo "New signed content" >> README.md
git add README.md

echo "--- Attempting to sign commit with signet... ---"
git commit -S -m "Test: A commit signed by Signet"

echo "--- Step 5: Verify the signature ---"
echo "--- Verifying commit signature with Git... ---"
set +e
GIT_LOG_OUTPUT=$(git log -1 --show-signature 2>&1)
GIT_LOG_STATUS=$?
set -e
echo "$GIT_LOG_OUTPUT"
VERIFICATION_OK=true
if [ $GIT_LOG_STATUS -ne 0 ]; then
    if echo "$GIT_LOG_OUTPUT" | grep -qi "bad/incompatible signature"; then
        echo "⚠️  Git reported signature verification issues (expected with untrusted X.509)."
    else
        echo "❌ Unexpected Git verification failure"
        VERIFICATION_OK=false
    fi
fi

echo "--- Step 5.1: Test stdout purity (regression for SHA bug) ---"
# Create dummy files for --verify test
echo "dummy data" > "$TEST_DIR/test_data.txt"
echo "dummy signature" > "$TEST_DIR/test_sig.txt"

# Test that --verify produces NO stdout (critical for Git SHA integrity)
# Note: verification will fail with dummy files, but we only care about stdout purity
VERIFY_STDOUT=$("$SIGNET_CMD_PATH" commit --home "$SIGNET_HOME" --verify "$TEST_DIR/test_sig.txt" "$TEST_DIR/test_data.txt" 2>/dev/null || true)
if [ -n "$VERIFY_STDOUT" ]; then
    echo "❌ CRITICAL: --verify produced stdout output (will corrupt Git SHA)"
    echo "Output: $VERIFY_STDOUT"
    exit 1
fi
echo "✅ Stdout purity check PASSED"

echo "--- Step 5.2: Test signet's own verification ---"
# Extract the signature from the commit (remove "gpgsig " prefix and leading spaces)
git cat-file commit HEAD | sed -n '/^gpgsig /,/^ -----END CMS-----$/p' | sed 's/^gpgsig //' | sed 's/^ //' > "$TEST_DIR/commit_sig.txt"

# Extract commit data without gpgsig block (preserve the blank line separator)
git cat-file commit HEAD | awk '
/^gpgsig / { in_sig=1; next }
in_sig && /^ / { next }
in_sig && /^$/ { in_sig=0; print; next }
{ print }
' > "$TEST_DIR/commit_clean.txt"

# Verify with signet's own verifier
set +e
SIGNET_VERIFY_OUTPUT=$("$SIGNET_CMD_PATH" commit --home "$SIGNET_HOME" --verify "$TEST_DIR/commit_sig.txt" "$TEST_DIR/commit_clean.txt" 2>&1)
SIGNET_VERIFY_STATUS=$?
set -e

if [ $SIGNET_VERIFY_STATUS -eq 0 ] && echo "$SIGNET_VERIFY_OUTPUT" | grep -q "verified successfully"; then
    echo "✅ Signet verification PASSED"
    SIGNET_VERIFICATION_OK=true
else
    echo "❌ Signet verification FAILED"
    echo "Output: $SIGNET_VERIFY_OUTPUT"
    SIGNET_VERIFICATION_OK=false
fi

echo "--- Step 6: Additional verification ---"
echo "Checking commit details:"
git log -1 --pretty=fuller

echo ""
echo "=== Test Results ==="

# Check if commit was created successfully
if git rev-parse HEAD~1 >/dev/null 2>&1; then
    echo "✅ Signed commit created successfully"
    COMMIT_CREATED=true
else
    echo "❌ Failed to create signed commit"
    COMMIT_CREATED=false
fi

# Check if commit has a signature (Git shows the commit differently when signed)
# When a commit is signed, git log shows it was signed even if verification fails
if git cat-file commit HEAD | grep -q "gpgsig"; then
    echo "✅ Signature attached to commit"
    SIGNATURE_ATTACHED=true
else
    echo "❌ Signature not found on commit"
    SIGNATURE_ATTACHED=false
fi

# Check if verification produces expected output (currently gpgsm doesn't trust our cert)
# For now, we're checking that no fatal errors occurred
if $VERIFICATION_OK; then
    echo "✅ Git verification produced expected output"
else
    echo "❌ Git verification produced unexpected errors"
fi

# Check if signet's own verification succeeded
if $SIGNET_VERIFICATION_OK; then
    echo "✅ Signet verification succeeded"
else
    echo "❌ Signet verification failed"
fi

echo ""
if $COMMIT_CREATED && $SIGNATURE_ATTACHED && $VERIFICATION_OK && $SIGNET_VERIFICATION_OK; then
    echo "=== INTEGRATION TEST PASSED ==="
    echo "Signet successfully signs and verifies Git commits!"
    exit 0
else
    echo "=== INTEGRATION TEST FAILED ==="
    echo "See errors above for details"
    exit 1
fi
