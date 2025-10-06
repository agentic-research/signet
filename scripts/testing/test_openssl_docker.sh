#!/bin/bash
# Run OpenSSL verification test in Docker - completely self-contained

set -e

echo "🐳 Running Signet OpenSSL verification in Docker..."
echo

# Build and run test in one shot
docker run --rm -v "$(pwd)":/signet:ro alpine:latest sh -c '
set -e

echo "📦 Installing dependencies..."
apk add --no-cache bash openssl go git make gcc musl-dev >/dev/null 2>&1

echo "🔨 Building signet..."
cd /signet
cp -r . /build
cd /build
make build >/dev/null 2>&1

echo "🔑 Initializing Signet..."
mkdir -p /test/.signet
cd /test
/build/signet commit --home /test/.signet --init --insecure

echo "✍️  Creating test message..."
echo "Test commit message for OpenSSL verification" > message.txt

echo "📝 Generating CMS signature..."
/build/signet commit --home /test/.signet < message.txt > signature.pem 2>stderr.txt

echo "🧪 Testing stdout purity (regression for SHA bug)..."
# Verify that --verify produces NO stdout (critical for Git compatibility)
/build/signet commit --home /test/.signet --verify signature.pem message.txt > verify_stdout.txt 2>&1
if [ -s verify_stdout.txt ]; then
    echo "❌ CRITICAL: --verify produced stdout output (will corrupt Git SHA)"
    cat verify_stdout.txt
    exit 1
fi
echo "✅ Stdout purity check PASSED"

echo "🔍 Verifying with OpenSSL..."
# Extract the certificate from the signature
openssl cms -verify -in signature.pem -inform PEM -noverify -certfile signature.pem -out /dev/null

if [ $? -eq 0 ]; then
    echo "✅ OpenSSL verification PASSED!"

    echo
    echo "📊 Signature details:"
    openssl cms -cmsout -print -in signature.pem -inform PEM 2>/dev/null | head -20
else
    echo "❌ OpenSSL verification FAILED!"
    exit 1
fi
'

echo
echo "✨ Test complete! Signet CMS signatures are OpenSSL-compatible."
