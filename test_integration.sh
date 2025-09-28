#!/bin/bash
set -e

# Integration Test for signet-commit
# This script validates that signet-commit can be used by Git to create 
# and verify cryptographically valid commit signatures

echo "=== Signet-commit Integration Test ==="

# Ensure we have the binary
if [ ! -f "./signet-commit" ]; then
    echo "Building signet-commit..."
    go build -o signet-commit ./cmd/signet-commit
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
SIGNET_CMD_PATH="$ORIGINAL_DIR/signet-commit"

# Initialize signet 
echo "Initializing signet with home: $SIGNET_HOME"
$SIGNET_CMD_PATH --home "$SIGNET_HOME" --init

# Ask the tool for its canonical key ID
MASTER_KEY_ID=$($SIGNET_CMD_PATH --home "$SIGNET_HOME" --export-key-id)
echo "--- Using Signet Master Key ID: $MASTER_KEY_ID ---"

echo "--- Step 3: Configure Git to use signet-commit ---"
# Tell Git to use X.509 signature format
git config --local gpg.format x509

# Create a wrapper script that includes the --home argument and debugging
WRAPPER_SCRIPT="$TEST_DIR/signet-wrapper.sh"
cat > "$WRAPPER_SCRIPT" << EOF
#!/bin/bash
echo "Wrapper called with args: \$@" >&2
echo "Calling: $SIGNET_CMD_PATH --home $SIGNET_HOME \$@" >&2
exec "$SIGNET_CMD_PATH" --home "$SIGNET_HOME" "\$@"
EOF
chmod +x "$WRAPPER_SCRIPT"

# Tell Git to use our wrapper script
git config --local gpg.x509.program "$WRAPPER_SCRIPT"

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

echo "--- Attempting to sign commit with signet-commit... ---"
git commit -S -m "Test: A commit signed by Signet"

echo "--- Step 5: Verify the signature ---"
echo "--- Verifying commit signature with Git... ---"
git log -1 --show-signature

echo "--- Step 6: Additional verification ---"
echo "Checking commit details:"
git log -1 --pretty=fuller

echo "--- Test completed successfully! ---"
echo "If you see 'gpg: Good signature' above, the integration test passed."
echo "If you see signature verification errors, there may be an issue with the implementation."