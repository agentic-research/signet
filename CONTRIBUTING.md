# Contributing to Signet

Thank you for your interest in contributing! This guide will help you get started.

## Table of Contents
1. [Development Setup](#1-development-setup)
2. [Code Style & Conventions](#2-code-style--conventions)
3. [Pull Request Process](#3-pull-request-process)
4. [Good First Issues](#4-good-first-issues)
5. [Community & Communication](#5-community--communication)

---

## 1. Development Setup

### Prerequisites

- **Go 1.25+** - Required for building the project
- **OpenSSL** - For signature verification
- **Git** - Version control
- **(Optional) Docker** - For integration testing

### Clone and Build

```bash
git clone https://github.com/jamestexas/signet.git
cd signet
make build
```

This produces the `./signet` binary with subcommands.

### Run Tests

```bash
# Unit tests
make test

# Integration tests (requires Docker)
make integration-test

# Quick development cycle
make clean build test
```

### Code Quality Tools

```bash
make fmt      # Format code
make lint     # Run linters (requires golangci-lint)
make security # Security scan (requires gosec)
```

### Development Workflow

```bash
# Typical workflow
git checkout -b feature/my-feature
# Make changes
make fmt lint test
git commit -m "feat: add my feature"
git push origin feature/my-feature
# Open PR
```

---

## 2. Code Style & Conventions

### Go Code Style

- **Follow standard Go conventions** - Use `gofmt` for formatting
- **Package names:** Lowercase, no underscores (e.g., `signet`, `middleware`)
- **Error handling:** Always check errors, wrap with context using `fmt.Errorf("context: %w", err)`
- **Comments:** Use godoc style for exported functions
  ```go
  // Sign generates a cryptographic signature for the given data.
  // It returns the signature bytes and any error encountered.
  func Sign(data []byte) ([]byte, error) {
      // implementation
  }
  ```

### Commit Messages

Use conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Maintenance tasks

**Example:**
```
feat(middleware): add nonce replay prevention

Implement time-windowed nonce store to prevent replay attacks.
Uses Redis backend for distributed deployments.

Closes #42
```

### Testing Requirements

- **All new features require tests**
- **Aim for >80% coverage** on new code
- **Integration tests** for user-facing features
- **Table-driven tests** for multiple test cases:
  ```go
  func TestSign(t *testing.T) {
      tests := []struct {
          name    string
          input   []byte
          wantErr bool
      }{
          {"valid input", []byte("test"), false},
          {"empty input", []byte{}, true},
      }
      for _, tt := range tests {
          t.Run(tt.name, func(t *testing.T) {
              // test implementation
          })
      }
  }
  ```

### Documentation Standards

- **Update CLAUDE.md** if adding new build commands or workflows
- **Update README.md** for user-facing changes
- **Add godoc comments** for all exported functions
- **Include examples** in package documentation

---

## 3. Pull Request Process

### Before Submitting

1. **Fork the repository** and create a feature branch
2. **Make your changes** with tests and documentation
3. **Run quality checks:**
   ```bash
   make fmt lint test
   ```
4. **Ensure all tests pass** locally

### PR Description Template

Use this template for your PR description:

```markdown
## What

Brief description of changes (1-2 sentences)

## Why

Motivation and context. What problem does this solve?

## Testing

How you tested this change:
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] `make test` passes
- [ ] `make lint` passes with no warnings
- [ ] Breaking changes documented
```

### Review Process

1. **Maintainer reviews** your PR (usually within 2-3 days)
2. **Address feedback** promptly
3. **Keep commits clean** - squash if requested
4. **Maintainer merges** once approved

### After Merge

- Your contribution will be included in the next release
- You'll be added to the contributors list
- Consider joining community discussions for future direction

---

## 4. Good First Issues

New contributors should look for issues tagged:

- [`good-first-issue`](https://github.com/jamestexas/signet/labels/good-first-issue) - Beginner-friendly
- [`help-wanted`](https://github.com/jamestexas/signet/labels/help-wanted) - Contributions welcome
- [`documentation`](https://github.com/jamestexas/signet/labels/documentation) - Documentation improvements

### High-Impact Contribution Areas

#### Core Protocol (Requires: CBOR/COSE knowledge)

From [DEVELOPMENT_ROADMAP.md Phase 1](./DEVELOPMENT_ROADMAP.md#phase-1-core-protocol-completion-months-1-2):

- Complete CBOR token structure with missing fields
- Implement SIG1 wire format
- Add COSE_Sign1 support in `pkg/crypto/cose`
- Build capability system (cap_id computation)

**Good for:** Cryptography enthusiasts, protocol implementers

#### Language SDKs (Requires: Language expertise)

From [DEVELOPMENT_ROADMAP.md Phase 5](./DEVELOPMENT_ROADMAP.md#phase-5-sdk--key-storage-months-4-5):

- **Python SDK** - Implement client library for Python
- **JavaScript/TypeScript SDK** - Node.js and browser support
- **Rust implementation** - Systems programming implementation

**Good for:** Polyglot developers, library authors

#### Security (Requires: Security background)

From [DEVELOPMENT_ROADMAP.md Phase 7](./DEVELOPMENT_ROADMAP.md#phase-7-production-hardening-months-6-7):

- Key storage encryption (OS keychain integration)
- Fuzzing test suite development
- Security audit assistance
- Penetration testing

**Good for:** Security researchers, penetration testers

#### Documentation (Requires: Technical writing)

- Migration guides (from JWT, GPG, OAuth)
- Tutorial creation (step-by-step guides)
- API documentation improvements
- Architecture diagrams

**Good for:** Technical writers, educators

#### HTTP Middleware (Requires: Go web development)

From [DEVELOPMENT_ROADMAP.md Phase 4](./DEVELOPMENT_ROADMAP.md#phase-4-http-authentication-months-3-4-parallel-with-phase-3):

- Framework adapters (Express.js, FastAPI, Spring Boot)
- Request canonicalization fixes
- Signature verification improvements

**Good for:** Web developers, framework contributors

---

## 5. Community & Communication

### GitHub Discussions

Primary forum for community interaction:

- **[Q&A category](https://github.com/jamestexas/signet/discussions/categories/q-a)** - Ask questions
- **[Ideas category](https://github.com/jamestexas/signet/discussions/categories/ideas)** - Propose features
- **[Roadmap category](https://github.com/jamestexas/signet/discussions/categories/roadmap)** - Discuss priorities

### Issue Tracker

For bugs and feature requests:

- **[Bug reports](https://github.com/jamestexas/signet/issues/new?labels=bug)** - Report issues
- **[Feature requests](https://github.com/jamestexas/signet/issues/new?labels=enhancement)** - Suggest features

**Before opening an issue:**
1. Search existing issues to avoid duplicates
2. Provide clear reproduction steps for bugs
3. Include relevant version information

### Code of Conduct

Be respectful, constructive, and collaborative. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

**Expected behavior:**
- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community

**Unacceptable behavior:**
- Harassment, trolling, or insulting comments
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

### Response Times

- **Issues:** We aim to respond within 3 business days
- **Pull requests:** First review within 2-3 days
- **Security issues:** Report privately, immediate response

---

## Getting Help

Stuck? Reach out:

1. **Comment on the relevant issue** - Maintainers will respond
2. **Start a [GitHub Discussion](https://github.com/jamestexas/signet/discussions)** - Community support
3. **Check [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md)** - Understand project context
4. **Read [ARCHITECTURE.md](./ARCHITECTURE.md)** - Understand design decisions

---

## Recognition

Contributors are recognized in:

- **Release notes** - Mentioning specific contributions
- **Contributors list** - Automatically updated via GitHub
- **Community highlights** - Featured in discussions

---

**Thank you for contributing to Signet!** Every contribution, no matter how small, helps build a more secure authentication ecosystem.

**Questions about this guide?** Open a [discussion](https://github.com/jamestexas/signet/discussions/new?category=q-a)
