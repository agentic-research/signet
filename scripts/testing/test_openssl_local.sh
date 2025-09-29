#!/bin/bash
# Test OpenSSL verification locally (no Docker needed)

set -e

echo "=== Testing Signet OpenSSL Verification ==="
echo

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create a test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT

echo "📁 Test directory: $TEST_DIR"
cd "$TEST_DIR"

# Find signet-commit
if [ -x "/usr/local/bin/signet-commit" ]; then
    SIGNET_CMD="/usr/local/bin/signet-commit"
elif [ -x "$(pwd)/signet-commit" ]; then
    SIGNET_CMD="$(pwd)/signet-commit"
else
    echo -e "${RED}❌ signet-commit not found. Run 'make build && sudo make install'${NC}"
    exit 1
fi

echo "🔑 Initializing Signet..."
$SIGNET_CMD --home "$TEST_DIR/.signet" --init

echo "✍️  Creating test message..."
echo "Test commit message for OpenSSL verification" > message.txt

echo "📝 Generating CMS signature..."
$SIGNET_CMD --home "$TEST_DIR/.signet" < message.txt > signature.pem

echo
echo "📊 Signature structure:"
cat signature.pem | head -5

echo
echo "🔍 Extracting certificate from signature..."
# The CMS signature should contain the certificate
# Extract it for OpenSSL verification
openssl cms -in signature.pem -inform PEM -print -noout 2>/dev/null | grep -A 20 "certificates:" || true

echo
echo "🔍 Testing OpenSSL verification..."
# Try different verification approaches

# Method 1: Basic verification with -binary flag (critical for detached signatures!)
echo -n "  Method 1 (with -binary flag): "
if openssl cms -verify -in signature.pem -inform PEM -noverify -content message.txt -binary > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    echo "    Trying without -binary flag..."
    if openssl cms -verify -in signature.pem -inform PEM -noverify -content message.txt > /dev/null 2>&1; then
        echo -e "    ${YELLOW}⚠️  Works without -binary (text mode)${NC}"
    fi
fi

# Method 2: Extract and verify structure
echo -n "  Method 2 (ASN.1 structure): "
if openssl asn1parse -in signature.pem -inform PEM > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Valid ASN.1${NC}"
else
    echo -e "${RED}❌ Invalid ASN.1${NC}"
fi

# Method 3: Check if it's proper PKCS#7/CMS
echo -n "  Method 3 (CMS format): "
if openssl cms -in signature.pem -inform PEM -cmsout -print -noout > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Valid CMS${NC}"
else
    echo -e "${RED}❌ Invalid CMS${NC}"
fi

echo
echo "📋 Detailed CMS structure:"
openssl cms -in signature.pem -inform PEM -cmsout -print -noout 2>&1 | head -30 || true

echo
echo "✨ Test complete!"