# pkg/http/header

Parser for Signet-Proof HTTP headers.

## Status: 🚧 Development (Parser Works!)

Wire format parser is implemented. Integration with verification is pending.

## What It Does

Parses `Signet-Proof` headers from HTTP requests:

```
Signet-Proof: v1;m=compact;t=<token>;jti=<jti>;cap=<cap>;s=<sig>;n=<nonce>;ts=<timestamp>
```

## Files

- `parser.go` - Header parsing with security hardening

## Parser Features

✅ **Implemented:**
- Parses all header fields
- Base64URL decoding
- Field validation (sizes, required fields)
- Duplicate field detection
- Size limits (8KB header, 4KB token)
- Security hardened based on review

❌ **Not Yet Implemented:**
- Signature verification
- Token validation
- Request canonicalization
- Integration with EPR verification

## Security Hardening

Based on security review, the parser:
- Rejects duplicate fields (prevents confusion attacks)
- Limits header size to 8KB (prevents DoS)
- Limits token size to 4KB
- Validates field sizes (JTI/nonce must be 16 bytes)
- Returns generic errors to clients

## Usage Example

```go
header := "v1;m=compact;t=...;jti=...;ts=1234567890;..."
proof, err := ParseSignetProof(header)
if err != nil {
    // Invalid header format
}

// Access parsed fields
jti := proof.JTI           // []byte (16 bytes)
timestamp := proof.Timestamp // int64
signature := proof.Signature // []byte (64+ bytes)
```

## Demo Usage

See `demo/http-auth/` for a working example that shows replay protection using this parser.

## Next Steps for v1.0

- Wire up signature verification
- Implement request canonicalization
- Integrate with pkg/crypto/epr for two-step verification
- Add middleware adapters for popular frameworks
