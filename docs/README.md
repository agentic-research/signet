# Documentation Structure

This directory contains technical documentation for the Signet project.

## Organization

### [`design/`](./design/)
Stable design documents explaining technical choices and architecture:
- `001-signet-tokens.md` - Token format and structure
- `002-protocol-spec.md` - Wire format and protocol
- `003-sdk.md` - SDK architecture
- `004-bridge-certs.md` - Federated identity certificates
- `005-memory-security.md` - Sensitive data handling
- `006-revocation.md` - Revocation strategy
- `007-http-pop.md` - HTTP proof-of-possession

### [`implementation/`](./implementation/)
Work-in-progress feature implementation guides:
- `revocation-sequence.md` - Step-by-step revocation implementation
- `revocation-interface.md` - Revocation API design

These documents are living artifacts used during development and may become less relevant after feature completion.

### Root Documentation
- `problem-statement.md` - Why Signet exists, the problem it solves
- `PERFORMANCE.md` - Benchmarks and performance analysis

## Finding What You Need

- **Understanding the project**: Start with [`../README.md`](../README.md) and `problem-statement.md`
- **Current status**: See [`../DEVELOPMENT_ROADMAP.md`](../DEVELOPMENT_ROADMAP.md)
- **Technical details**: Explore `design/` docs
- **Contributing**: See [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
- **Architecture overview**: See [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
