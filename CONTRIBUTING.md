# Contributing to Signet

Thank you for your interest in contributing to Signet! This document provides guidelines for contributions.

## Code of Conduct

Be respectful and constructive. We're building security-critical software together.

## How to Contribute

### Reporting Issues
- Check existing issues first
- Provide reproduction steps
- Include system information
- For security vulnerabilities, please email directly (don't use public issues)

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linters (`make lint`)
6. Commit with descriptive messages
7. Push to your fork
8. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/jamestexas/signet.git
cd signet

# Build the project
make build

# Run tests
make test

# Run integration tests
make integration-test

# Install pre-commit hooks
pre-commit install
```

### Code Style
- Follow Go conventions
- Run `go fmt` before committing
- Add tests for new functionality
- Update documentation as needed

### Testing
- Unit tests required for new features
- Integration tests for cross-component functionality
- Benchmarks for performance-critical code

### Documentation
- Update README.md for user-facing changes
- Update technical docs in `docs/`
- Add ADRs for architectural decisions

## Priority Areas

### High Priority
- Security reviews and audits
- Python and JavaScript SDKs
- HTTP middleware adapters
- Documentation improvements

### Research Areas
- Post-quantum cryptography
- Hardware security module support
- Service mesh integration
- Anonymous authentication

## Questions?

Open an issue or start a discussion. We're here to help!

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
