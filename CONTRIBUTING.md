# Contributing to Signet

First off, thank you for considering contributing to Signet! It's people like you that will help make Signet a revolutionary authentication protocol.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Current Priorities

We're focusing on specific areas where help would be most valuable:

1. **HTTP Middleware Adapters** (High Priority)
   - Build adapters for popular Go frameworks (Gin, Echo, Chi, Fiber)
   - Each adapter should implement the `http.Handler` interface
   - See `pkg/http/` for the wire format specification

2. **Testing & Quality**
   - Expand test coverage (current goal: >80%)
   - Add integration tests for real-world scenarios
   - Performance benchmarking

3. **Documentation**
   - Improve installation guides for different platforms
   - Add more examples and use cases
   - Write tutorials for common integration patterns

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps to reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed and expected
* Include system details (OS, Go version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested enhancement
* Provide specific examples to demonstrate the feature
* Explain why this enhancement would be useful
* List any similar features in other projects

## Development Setup

### Prerequisites

```bash
# Required
go 1.21+
make
git

# Optional (for testing)
openssl
gpg
```

### Local Development

1. Fork and clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/signet.git
cd signet
```

2. Install dependencies:
```bash
go mod download
```

3. Build the project:
```bash
make build
```

4. Run tests:
```bash
make test
```

5. Run linting:
```bash
make lint  # requires golangci-lint
```

### Project Structure

```
signet/
├── cmd/              # Executable commands
│   └── signet-commit/  # Git signing tool
├── pkg/              # Library packages
│   ├── signet/       # Core protocol
│   ├── crypto/       # Cryptographic operations
│   ├── cms/          # CMS/PKCS#7 implementation
│   └── http/         # HTTP authentication
├── scripts/          # Build and test scripts
└── docs/            # Documentation and ADRs
```

## Pull Request Process

1. **Before Starting**
   - Check if there's an existing issue for your change
   - For large changes, open an issue first to discuss

2. **Development**
   - Create a feature branch from `main`
   - Write tests for any new functionality
   - Ensure all tests pass (`make test`)
   - Update documentation as needed

3. **Commit Messages**
   - Use conventional commits format:
     - `feat:` New feature
     - `fix:` Bug fix
     - `docs:` Documentation only
     - `refactor:` Code change that neither fixes a bug nor adds a feature
     - `test:` Adding missing tests
     - `perf:` Performance improvement

4. **Submitting**
   - Push your branch and create a pull request
   - Link any related issues
   - Ensure CI checks pass
   - Be responsive to review feedback

### Code Style

- Follow standard Go conventions
- Run `gofmt` on all code
- Keep functions small and focused
- Add comments for exported functions
- Avoid unnecessary complexity

### Testing Guidelines

- Write table-driven tests where appropriate
- Include both positive and negative test cases
- Test edge cases and error conditions
- Aim for >80% code coverage
- Use meaningful test names that describe what's being tested

## Design Philosophy

When contributing, please keep these principles in mind:

1. **Security First**: Every feature must consider security implications
2. **Offline-First**: Features should work without network connectivity where possible
3. **Simplicity**: Prefer simple, clear solutions over clever ones
4. **Performance**: Consider performance, but not at the expense of security
5. **Compatibility**: Maintain backward compatibility when possible

## Getting Help

- Open an issue for bugs or feature requests
- Start a discussion for design questions
- Check existing issues and discussions first

## Recognition

Contributors will be recognized in:
- The project's contributor graph
- Release notes for significant contributions
- A future CONTRIBUTORS.md file as the project grows

## License

By contributing to Signet, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Signet! Your efforts help build a more secure authentication future. 🔐