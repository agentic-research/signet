# Security Policy

## Project Status

⚠️ **EXPERIMENTAL SOFTWARE** - v0.1.0 is an alpha release not suitable for production use.

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.1.0   | :white_check_mark: | Alpha - Development only |

## Known Security Limitations

### v0.1.0 Alpha
- Keys stored in the OS keyring by default; falls back to plaintext `~/.signet/master.key` when the keyring is unavailable or Signet is initialized with `--insecure`
- `signet authority` and other long-running automation currently use file-based master keys (secure keyring support planned)
- No security audit performed
- APIs will change before v1.0
- Tested primarily on macOS (Linux should work but minimal testing)

#### Keyring memory safety
- OS keyring integration uses `github.com/zalando/go-keyring`, which stores secrets as Go strings
- Go strings are immutable, so secrets may persist in process memory until garbage collection
- Private keys are zeroed after use, but short-lived remnants may exist (see `pkg/cli/keystore/secure.go`)

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

When using Signet v0.1.0:
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

- **Signatures**: Ed25519 (RFC 8032), ML-DSA-44 (FIPS 204) via cloudflare/circl
- **Hashing**: SHA-256, BLAKE3
- **Encoding**: CMS/PKCS#7 (RFC 5652) with Ed25519 (RFC 8410)
- **Wire Format**: COSE Sign1 with SIG1 compact encoding
- **Certificates**: X.509 v3 with 5-minute validity
- **Key derivation**: Not yet implemented (planned)

## External Dependency Vetting

Signet follows a **minimal wrapper code** philosophy for cryptographic and hardware operations. External dependencies are carefully vetted:

### Vetting Criteria

1. **Memory Safety**: Dependencies that handle cryptographic material must demonstrate proper memory zeroization
2. **Audit Trail**: Preferably maintained by organizations with security expertise
3. **API Stability**: Mature APIs with documented security properties
4. **Build Tag Isolation**: CGO dependencies are isolated behind build tags to keep the default Pure Go build portable

### Current Dependencies

#### Core Cryptography (Always Required)
- **`golang.org/x/crypto`** - Official Go crypto extensions
  - Maintained by Go team
  - Used for Ed25519 operations
  - Well-audited standard library extensions

- **`github.com/agentic-research/go-cms`** - CMS/PKCS#7 with Ed25519
  - Extracted from this project for reuse
  - OpenSSL-compatible signatures
  - No CGO dependencies

#### Hardware Signers (Optional, CGO Required)
- **`github.com/agentic-research/go-platform-signers`** - Hardware token integration
  - Public repository: https://github.com/agentic-research/go-platform-signers
  - Provides `crypto.Signer` implementations for PKCS#11
  - Only compiled when `-tags=pkcs11` is specified
  - **Status**: Under active security review
  - **PIN Handling**: Delegates PIN zeroization to underlying PKCS#11 module

- **`github.com/miekg/pkcs11`** - PKCS#11 Go bindings (transitive via go-platform-signers)
  - Widely used in Go ecosystem
  - Thin CGO wrapper around native PKCS#11 libraries
  - Security properties depend on the underlying HSM/token vendor libraries

### Adding New Dependencies

Before adding a new cryptographic or hardware dependency:

1. **Security Review**:
   - Check for memory safety issues (buffer overflows, use-after-free)
   - Verify zeroization of sensitive material
   - Review issue tracker for security vulnerabilities

2. **Maintainer Assessment**:
   - Who maintains it? (Individual, organization, community)
   - How active is development?
   - How are security issues handled?

3. **Build Tag Strategy**:
   - Pure Go implementations: default build
   - CGO/platform-specific: behind build tags
   - Document the tradeoff between portability and features

4. **Documentation**:
   - Add to this SECURITY.md with vetting rationale
   - Document security properties and limitations
   - Clarify who is responsible for memory safety

## Acknowledgments

Thanks to researchers and developers who review and provide feedback on Signet's security model.
