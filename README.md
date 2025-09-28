# Signet

An offline-first Git commit signing tool using ephemeral X.509 certificates and Ed25519 cryptography.

## Features

- ✅ **Completely Offline**: No network required for signing
- ✅ **Ephemeral Certificates**: Short-lived (5-minute) X.509 certificates  
- ✅ **Ed25519 Cryptography**: Modern, fast elliptic curve signatures
- ✅ **Git Integration**: Drop-in replacement for GPG signing
- ✅ **Self-Sovereign**: Your master key never leaves your device
- ✅ **CMS/PKCS#7 Output**: Industry standard signature format

## Quick Start

```bash
# Install dependencies (macOS)
brew install gnupg go

# Build signet-commit
go build -o signet-commit ./cmd/signet-commit

# Initialize (creates ~/.signet/master.key)
./signet-commit --init

# Configure Git
git config --global gpg.format x509
git config --global gpg.x509.program $(pwd)/signet-commit  
git config --global user.signingKey $(./signet-commit --export-key-id)
git config --global commit.gpgsign true

# Sign commits!
git commit -S -m "My signed commit"
```

## Prerequisites

### Required Dependencies

- **Go 1.21+**: For building the binary
- **GnuPG**: Provides `gpgsm` required for Git's X.509 signature verification

```bash
# macOS
brew install go gnupg

# Ubuntu/Debian  
sudo apt install golang-go gnupg-agent

# Fedora/RHEL
sudo dnf install golang gnupg2
```

**Important**: The `gpgsm` tool from GnuPG is required for Git's X.509 signature support, even when using a custom signing program like signet-commit.

## Installation

```bash
# Clone the repository
git clone https://github.com/jamestexas/signet.git
cd signet

# Build the binary
go build -o signet-commit ./cmd/signet-commit

# Optional: Install to PATH
sudo cp signet-commit /usr/local/bin/

# Initialize Signet (creates ~/.signet/master.key)
./signet-commit --init
```

## Git Configuration

After installation, configure Git to use signet-commit:

```bash
# Set signature format to X.509
git config --global gpg.format x509

# Set signet-commit as the X.509 program (use full path)
git config --global gpg.x509.program /path/to/signet-commit

# Set your signing key (use the exported key ID)
git config --global user.signingKey $(signet-commit --export-key-id)

# Enable automatic commit signing
git config --global commit.gpgsign true
```

## How It Works

1. **Master Key**: Your identity is anchored to a local Ed25519 key pair
2. **Local CA**: Acts as its own certificate authority using the master key
3. **Ephemeral Certificates**: Issues short-lived certs (5 minutes) for each signing operation
4. **CMS/PKCS#7 Signatures**: Creates industry-standard detached signatures
5. **Offline-First**: No network required at any step

## Project Structure

```
signet/
├── pkg/                    # libsignet core library
│   ├── signet/            # Token structures
│   ├── crypto/            # Cryptographic operations
│   └── attest/            # X.509 certificate generation
├── cmd/                   
│   └── signet-commit/     # Git commit signing tool
└── docs/                  # Documentation
```

## Troubleshooting

### macOS: "gpg failed to sign the data"

On macOS, Apple Git requires binaries to be in trusted locations or properly code-signed. If `git commit -S` fails with "gpg failed to sign the data", the binary location is likely blocked by macOS security policy.

**Solution 1: Install to trusted location**
```bash
# Install to /usr/local/bin (trusted by Apple Git)
sudo cp signet-commit /usr/local/bin/signet-commit
sudo chmod 755 /usr/local/bin/signet-commit

# Update Git configuration  
git config --global gpg.x509.program /usr/local/bin/signet-commit
```

**Solution 2: Code-sign the binary**
```bash
# Code-sign for hardened runtime
codesign -s - -f --timestamp=none --options=runtime /path/to/signet-commit

# Then use the original path in Git config
git config --global gpg.x509.program /path/to/signet-commit
```

### Verifying Configuration

```bash
# Check Git configuration
git config --list | grep -E "(gpg|sign)"

# Test signet-commit directly
echo "test" | signet-commit --detach-sign

# Check that gpgsm is available
which gpgsm
```

## Development Status

- [x] Core architecture design
- [x] Ed25519 key operations  
- [x] Local CA implementation
- [x] CMS/PKCS#7 signature generation
- [x] Git integration (CLI)
- [x] Integration testing
- [ ] Signature verification testing
- [ ] Cross-platform testing
- [ ] CI/CD pipeline

## Security Model

- **Trust Anchor**: Local master key (never leaves device)
- **Ephemeral Keys**: Short-lived certificates (5 minutes)
- **Offline Operation**: No network attack surface
- **Simple**: Minimal complexity reduces bugs

## Contributing

This MVP is intentionally minimal. Features being deferred:
- Multi-device synchronization
- DID documents and resolution
- Alternative signature algorithms
- Hardware security modules
- Recovery mechanisms

See [ARCHITECTURE_MVP.md](ARCHITECTURE_MVP.md) for design details.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built as an offline-first complement to the [Sigstore](https://sigstore.dev) ecosystem.