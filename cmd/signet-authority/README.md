# Signet Authority

A prototype "Fulcio-for-people" service that authenticates users via OIDC and issues short-lived X.509 client identity certificates bound to their device's public key.

## Overview

The Signet Authority acts as a bridge between OIDC identity providers (like Google, GitHub) and device-specific cryptographic keys. Upon successful authentication, it issues an X.509 certificate that:
- Contains the user's verified email from the OIDC provider
- Is bound to the user's device public key
- Has a short validity period (default: 8 hours)
- Can be used for client authentication

## Setup

### 1. Generate Master Key

You can use either format:

**Option A: OpenSSL format (PKCS8)**
```bash
chmod +x generate-key.sh
./generate-key.sh
```

**Option B: Signet format (if you have signet-commit)**
```bash
signet-commit --init  # Creates key in ~/.signet/
# Then reference ~/.signet/master.key in your config
```

### 2. Configure OIDC Provider

1. Go to your OIDC provider (e.g., Google Cloud Console)
2. Create OAuth 2.0 credentials
3. Add `http://localhost:8080/callback` as an authorized redirect URI
4. Copy the Client ID and Client Secret

### 3. Create Configuration

```bash
cp config.json.example config.json
# Edit config.json with your values:
# - oidc_provider_url: Your OIDC provider's URL
# - oidc_client_id: Your OAuth client ID
# - oidc_client_secret: Your OAuth client secret
# - authority_master_key_path: Path to your master key
# - session_secret: Random 32-character string
```

## Running

```bash
go run . -config config.json
# Or build and run:
go build -o signet-authority
./signet-authority -config config.json
```

## Usage

### Client Flow

1. Generate device key pair (Ed25519)
2. Make request to `/login?device_key=<base64url-encoded-public-key>`
3. User is redirected to OIDC provider for authentication
4. After successful auth, user is redirected back to `/callback`
5. Server returns PEM-encoded X.509 certificate

### Example Client Request

```bash
# Generate a device key pair
openssl genpkey -algorithm ED25519 -out device-key.pem
openssl pkey -in device-key.pem -pubout -outform DER | base64 -w0 | tr '+/' '-_' | tr -d '=' > device-key.pub.b64url

# Initiate authentication
DEVICE_KEY=$(cat device-key.pub.b64url)
curl "http://localhost:8080/login?device_key=$DEVICE_KEY"
# This will redirect to OIDC provider for authentication
```

## API Endpoints

- `GET /login?device_key=<base64url-key>` - Initiates OIDC flow
- `GET /callback` - OIDC callback endpoint (not called directly)
- `GET /healthz` - Health check endpoint

## Security Considerations

- Master key must have 0600 permissions
- Session cookies are HttpOnly and Secure (when using HTTPS)
- State parameter prevents CSRF attacks
- Sessions expire after 5 minutes
- Certificates are short-lived (default 8 hours)

## Development

Run with verbose logging:
```bash
go run . -config config.json -verbose
```

## Architecture

The service follows this flow:
1. User provides device public key
2. OIDC authentication verifies user identity
3. Authority signs certificate binding identity to device key
4. User receives certificate for client authentication

This creates a trust chain:
- OIDC provider attests to user identity
- Authority attests that identity owns the device key
- Device key can sign requests proving possession
