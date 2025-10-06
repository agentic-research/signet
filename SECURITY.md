# Security Policy

## Project Status

⚠️ **EXPERIMENTAL SOFTWARE** - v0.0.1 is an alpha release not suitable for production use.

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.0.1   | :white_check_mark: | Alpha - Development only |

## Known Security Limitations

### v0.0.1 Alpha
- Keys stored in OS keyring (falls back to plaintext if keyring unavailable)
- Not all features migrated to secure storage yet
- No security audit performed
- APIs will change before v1.0
- Tested primarily on macOS (Linux should work but minimal testing)

### What IS Secure
- Ed25519 cryptographic operations
- Ephemeral key generation (5-minute lifetime)
- Domain separation implementation
- Memory zeroization for ephemeral keys

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via:
1. Email to the maintainer (see git history for contact)
2. Use GitHub's private vulnerability reporting (if enabled)

### What to Include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time
- Acknowledgment: Within 48 hours
- Initial assessment: Within 1 week
- Fix timeline: Depends on severity

## Security Best Practices

When using Signet v0.0.1:
1. **Do not use in production** - This is experimental software
2. **Protect master keys** - Store in secure locations with proper permissions
3. **Monitor key usage** - Check for unauthorized access to `~/.signet/`
4. **Test thoroughly** - Verify signatures work in your environment
5. **Stay updated** - Watch for security updates

## Future Security Improvements

Planned for v1.0:
- Encrypted key storage
- Password protection
- Hardware security module support
- Professional security audit
- Formal verification of cryptographic operations

## Cryptographic Details

- **Signatures**: Ed25519 (RFC 8032)
- **Hashing**: SHA-256, BLAKE3
- **Encoding**: CMS/PKCS#7 (RFC 5652) with Ed25519 (RFC 8410)
- **Certificates**: X.509 v3 with 5-minute validity
- **Key derivation**: Not yet implemented (planned)

## Acknowledgments

Thanks to researchers and developers who review and provide feedback on Signet's security model.
