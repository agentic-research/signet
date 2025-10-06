#!/bin/bash
# Test for stdout contamination during --verify (regression test for SHA prefix bug)
#
# This test ensures that `signet commit --verify` produces NO stdout output,
# which is critical for Git compatibility. Any stdout output will corrupt Git's
# internal processing and cause SHA prefix issues.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Testing: signet commit --verify stdout purity"
echo "========================================="

# Build signet
echo -e "${YELLOW}Building signet...${NC}"
go build -o ./bin/signet ./cmd/signet

# Create temp files for testing
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

SIG_FILE="$TMP_DIR/signature.asc"
DATA_FILE="$TMP_DIR/data.txt"

# Create dummy signature and data files (content doesn't matter for stdout test)
echo "dummy signature" > "$SIG_FILE"
echo "dummy data" > "$DATA_FILE"

echo -e "${YELLOW}Testing --verify stdout purity...${NC}"

# Capture stdout and stderr separately
STDOUT_FILE="$TMP_DIR/stdout.txt"
STDERR_FILE="$TMP_DIR/stderr.txt"

# Run signet commit --verify and capture output
# Note: We expect this to succeed (exit 0) but with EMPTY stdout
set +e
./bin/signet commit --verify "$SIG_FILE" "$DATA_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"
EXIT_CODE=$?
set -e

# Check 1: Exit code should be 0 (success)
if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}FAIL: Expected exit code 0, got $EXIT_CODE${NC}"
    echo "stderr output:"
    cat "$STDERR_FILE"
    exit 1
fi

# Check 2: stdout MUST be completely empty
if [ -s "$STDOUT_FILE" ]; then
    echo -e "${RED}FAIL: stdout is not empty!${NC}"
    echo -e "${RED}This will corrupt Git SHA processing${NC}"
    echo "stdout content:"
    cat "$STDOUT_FILE"
    echo "---"
    echo "stdout length: $(wc -c < "$STDOUT_FILE") bytes"
    exit 1
fi

echo -e "${GREEN}✓ Exit code is 0 (success)${NC}"
echo -e "${GREEN}✓ stdout is completely empty${NC}"
echo -e "${GREEN}✓ Git compatibility maintained${NC}"
echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
