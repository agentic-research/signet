#!/bin/bash
# Direct test of OpenSSL verification with our CMS signature

set -e

echo "=== Testing OpenSSL CMS Verification ==="
echo

# Create a test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT
cd "$TEST_DIR"

# Initialize signet
SIGNET_HOME="$TEST_DIR/.signet"
SIGNET_CMD="$OLDPWD/bin/signet-commit"

echo "1. Initializing signet..."
$SIGNET_CMD --home "$SIGNET_HOME" --init

# Create a test message
echo "Test commit message for OpenSSL verification" > message.txt

echo "2. Generating CMS signature..."
$SIGNET_CMD --home "$SIGNET_HOME" < message.txt > signature.pem

# Extract DER
sed '1d;$d' signature.pem | tr -d '\n' | base64 -d > signature.der

echo "3. Checking ASN.1 structure of SignedAttrs..."
echo "Looking for IMPLICIT [0] tag and attribute structure:"
openssl asn1parse -inform DER -in signature.der -i | grep -A20 "cont \[ 0 \]" | grep -A10 "signingTime\|messageDigest\|contentType" | head -20

echo
echo "4. Testing OpenSSL CMS verification..."
echo "First trying without -binary flag:"
if openssl cms -verify -inform DER -in signature.der -content message.txt -noverify 2>&1; then
    echo "✓ SUCCESS: OpenSSL verified the signature (without -binary)!"
else
    echo "✗ FAILED without -binary flag"
fi

echo
echo "Now trying WITH -binary flag (recommended for detached signatures):"
if openssl cms -verify -inform DER -in signature.der -content message.txt -noverify -binary 2>&1; then
    echo "✓ SUCCESS: OpenSSL verified the signature with -binary flag!"
else
    echo "✗ FAILED: OpenSSL cannot verify even with -binary"
    echo
    echo "Error details:"
    openssl cms -verify -inform DER -in signature.der -content message.txt -noverify -binary 2>&1 || true
fi

echo
echo "5. Testing with certificate extraction..."
if openssl cms -cmsout -print -inform DER -in signature.der 2>&1 | head -50; then
    echo "Structure parsed partially"
else
    echo "Cannot parse structure"
fi

echo
echo "=== Test Complete ==="