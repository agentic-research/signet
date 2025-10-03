#!/bin/bash
# Test script to verify CMS/PKCS#7 PEM headers with OpenSSL

set -e

echo "=== Testing CMS/PKCS#7 PEM Header Types ==="
echo

# Create a test message
echo "Test commit message" > test_message.txt

# Generate a test signature using signet-commit
echo "1. Generating signature with current implementation (SIGNED MESSAGE header)..."
./bin/signet-commit -S < test_message.txt > test_signature_original.pem 2>/dev/null

# Display the current PEM header
echo "Current PEM header type:"
head -n 1 test_signature_original.pem
echo

# Extract the DER content (base64 decoded)
echo "2. Extracting DER content..."
sed '1d;$d' test_signature_original.pem | base64 -d > test_signature.der

# Test 1: Try with CMS header
echo "3. Testing with CMS header..."
echo "-----BEGIN CMS-----" > test_signature_cms.pem
base64 < test_signature.der >> test_signature_cms.pem
echo "-----END CMS-----" >> test_signature_cms.pem

echo "Attempting OpenSSL verification with CMS header:"
if openssl cms -verify -binary -inform PEM -in test_signature_cms.pem -noverify -content test_message.txt -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse with CMS header!"
else
    echo "✗ FAILED: OpenSSL cannot parse with CMS header"
    exit 1
fi
echo

# Test 2: Try with PKCS7 header
echo "4. Testing with PKCS7 header..."
echo "-----BEGIN PKCS7-----" > test_signature_pkcs7.pem
base64 < test_signature.der >> test_signature_pkcs7.pem
echo "-----END PKCS7-----" >> test_signature_pkcs7.pem

echo "Attempting OpenSSL verification with PKCS7 header:"
if openssl cms -verify -binary -inform PEM -in test_signature_pkcs7.pem -noverify -content test_message.txt -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse with PKCS7 header!"
else
    echo "✗ FAILED: OpenSSL cannot parse with PKCS7 header"
    exit 1
fi
echo

# Also try with pkcs7 command instead of cms
echo "5. Testing PKCS7 header with pkcs7 command..."
if openssl pkcs7 -in test_signature_pkcs7.pem -inform PEM -print_certs 2>&1 | grep -q "subject="; then
    echo "✓ SUCCESS: OpenSSL pkcs7 command can parse with PKCS7 header!"
else
    echo "✗ FAILED: OpenSSL pkcs7 command cannot parse"
    exit 1
fi
echo

# Test the DER directly
echo "6. Testing DER format directly..."
if openssl cms -verify -binary -inform DER -in test_signature.der -noverify -content test_message.txt -out /dev/null 2>&1; then
    echo "✓ SUCCESS: OpenSSL can parse DER directly!"
else
    echo "✗ FAILED: OpenSSL cannot parse DER directly"
    echo "This suggests the ASN.1 structure itself might have issues"
    exit 1
fi
echo

# Analyze the ASN.1 structure
echo "7. Analyzing ASN.1 structure..."
echo "ASN.1 dump of our signature:"
openssl asn1parse -inform DER -in test_signature.der -i 2>&1 | head -20

# Clean up
rm -f test_message.txt test_signature*.pem test_signature.der

echo
echo "=== Test Complete ==="
