#!/bin/bash
# Test script to verify PEM header types with OpenSSL
# This test uses a pre-generated signature to focus on the PEM header issue

set -e

echo "=== Testing CMS/PKCS#7 PEM Header Types ==="
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
echo "Test commit message for PEM header verification" > test_message.txt

echo "2. Generating signature with current implementation..."
$SIGNET_CMD --home "$SIGNET_HOME" < test_message.txt > test_signature_original.pem

# Display the current PEM header
echo
echo "Current PEM header type:"
head -n 1 test_signature_original.pem
echo

# Extract the DER content
echo "3. Extracting DER content..."
sed '1d;$d' test_signature_original.pem | tr -d '\n' | base64 -d > test_signature.der

# Test with CMS header
echo "4. Testing with CMS header..."
(
    echo "-----BEGIN CMS-----"
    base64 test_signature.der | fold -w 64
    echo "-----END CMS-----"
) > test_signature_cms.pem

echo "Attempting OpenSSL verification with CMS header:"
if openssl cms -verify -inform PEM -in test_signature_cms.pem -noverify -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse with CMS header!"
    CMS_WORKS=true
else
    echo "✗ FAILED: OpenSSL cannot parse with CMS header"
    CMS_WORKS=false
fi
echo

# Test with PKCS7 header
echo "5. Testing with PKCS7 header..."
(
    echo "-----BEGIN PKCS7-----"
    base64 test_signature.der | fold -w 64
    echo "-----END PKCS7-----"
) > test_signature_pkcs7.pem

echo "Attempting OpenSSL verification with PKCS7 header:"
if openssl cms -verify -inform PEM -in test_signature_pkcs7.pem -noverify -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse with PKCS7 header!"
    PKCS7_WORKS=true
else
    echo "✗ FAILED: OpenSSL cannot parse with PKCS7 header"
    PKCS7_WORKS=false
fi
echo

# Also try with pkcs7 command
echo "6. Testing PKCS7 header with pkcs7 command..."
if openssl pkcs7 -in test_signature_pkcs7.pem -inform PEM -print 2>&1 | grep -q "pkcs7"; then
    echo "✓ SUCCESS: OpenSSL pkcs7 command can read structure!"
    PKCS7_CMD_WORKS=true
else
    echo "✗ FAILED: OpenSSL pkcs7 command cannot read"
    PKCS7_CMD_WORKS=false
fi
echo

# Test the DER directly
echo "7. Testing DER format directly..."
if openssl cms -verify -inform DER -in test_signature.der -noverify -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse DER directly!"
    echo "This confirms the ASN.1 structure is valid!"
else
    echo "✗ FAILED: OpenSSL cannot parse DER directly"
    echo "This suggests the ASN.1 structure itself has issues"
    
    # Try to get more details
    echo
    echo "Getting error details:"
    openssl cms -verify -inform DER -in test_signature.der -noverify -out /dev/null 2>&1 || true
fi
echo

# Show ASN.1 structure
echo "8. ASN.1 structure analysis:"
echo "First 30 lines of ASN.1 dump:"
openssl asn1parse -inform DER -in test_signature.der -i 2>&1 | head -30

echo
echo "=== Summary ==="
if $CMS_WORKS; then
    echo "✓ CMS header works with OpenSSL"
fi
if $PKCS7_WORKS; then
    echo "✓ PKCS7 header works with OpenSSL"
fi
if $PKCS7_CMD_WORKS; then
    echo "✓ PKCS7 command can read structure"
fi

if $CMS_WORKS || $PKCS7_WORKS; then
    echo
    echo "BREAKTHROUGH: The PEM header was indeed the issue!"
    echo "The ASN.1 structure appears to be correct."
    if $CMS_WORKS && $PKCS7_WORKS; then
        echo "Both CMS and PKCS7 headers work. CMS is more modern and preferred."
    elif $CMS_WORKS; then
        echo "Recommend using CMS header."
    else
        echo "Recommend using PKCS7 header."
    fi
else
    echo
    echo "Neither CMS nor PKCS7 headers work with OpenSSL."
    echo "The issue is likely in the ASN.1 structure itself."
fi

echo
echo "=== Test Complete ==="