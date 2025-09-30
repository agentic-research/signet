#!/bin/bash
# Script to generate an Ed25519 master key for the Signet Authority
#
# Note: This generates a PKCS8-formatted key for the Authority service.
# For regular signet operations, use 'signet-commit --init' instead.

KEY_FILE="authority-key.pem"

echo "Generating Ed25519 master key for Signet Authority..."
echo "Note: This is specifically for the Authority service, not for signet-commit"
echo ""

# Generate Ed25519 private key in PKCS8 format
openssl genpkey -algorithm ED25519 -out "$KEY_FILE"

if [ $? -eq 0 ]; then
    echo "Master key generated successfully: $KEY_FILE"
    echo ""
    echo "Key details:"
    openssl pkey -in "$KEY_FILE" -noout -text
    echo ""
    echo "Update your config.json with:"
    echo "  \"authority_master_key_path\": \"$(pwd)/$KEY_FILE\""
else
    echo "Failed to generate master key"
    exit 1
fi

# Set appropriate permissions
chmod 600 "$KEY_FILE"
echo ""
echo "Key file permissions set to 600 (read/write for owner only)"
