# Signet v1.0 Rebase Plan

## Goal
Create a clean, professional commit history for public release that tells the story of Signet's development in logical, reviewable chunks.

## Current State
- 37 commits total
- Mix of features, fixes, refactors, and documentation
- Need to consolidate into ~5-7 meaningful commits

## Target History Structure

### Commit 1: Core Protocol Foundation
**Squash:** Commits 1-12 (initial architecture through basic crypto)
```
feat: implement Signet core protocol with libsignet

- Ephemeral Proof Routines (EPR) for two-step verification
- CBOR token structures with deterministic serialization
- Ed25519 key management and signing interfaces
- Domain separation for cryptographic contexts
```

### Commit 2: Git Signing Implementation
**Squash:** Commits 13-25 (signet-commit and CMS work)
```
feat: add signet-commit CLI for Git signing with CMS/X.509

- GPG-compatible interface for git integration
- CMS/PKCS#7 implementation with Ed25519 support
- Local CA for short-lived certificates (5-minute default)
- Secure master key storage in ~/.signet/
```

### Commit 3: Production Hardening
**Squash:** Commits 26-30 (error handling, refactoring)
```
refactor: production-ready code with custom errors and testing

- Comprehensive error types with context
- Integration test suite with OpenSSL verification
- Memory zeroization for sensitive data
- Timing attack mitigations
```

### Commit 4: HTTP Middleware Foundation
**Keep separate:** Commits 31-34 (recent HTTP work)
```
feat: implement HTTP middleware wire format and security model

- ADR-002 compliant security implementation
- Minimal adapter pattern for existing infrastructure
- Production-ready wire format parser
- Foundation for service mesh integration
```

### Commit 5: Documentation and Architecture
**Squash:** Documentation commits
```
docs: comprehensive documentation and architecture decisions

- Architecture Decision Records (ADRs)
- Production deployment guide
- Security model documentation
- Contributing guidelines
```

### Commit 6: Prepare for Public Release
**New commit:** Current changes
```
docs: prepare for v1.0 public release

- Honest README reflecting current state
- CONTRIBUTING.md and CODE_OF_CONDUCT.md
- Clear roadmap for future development
```

## Rebase Commands

```bash
# 1. Start interactive rebase from root
git rebase -i --root

# 2. In editor, mark commits according to plan:
# - Use 'pick' for the first commit of each group
# - Use 'squash' for commits to be combined
# - Use 'reword' to update commit messages

# 3. For each squash group, craft meaningful commit message

# 4. After rebase, verify with:
git log --oneline
git log --stat

# 5. Force push to feature branch (NOT main yet):
git push -f origin feature/prepare-public-release
```

## Pre-Rebase Checklist
- [x] Create feature branch (feature/prepare-public-release)
- [x] Write honest README_v1.md
- [x] Create CONTRIBUTING.md
- [x] Create CODE_OF_CONDUCT.md
- [ ] Commit current changes
- [ ] Execute rebase
- [ ] Verify rebased history
- [ ] Replace README.md with README_v1.md
- [ ] Final review
- [ ] Merge to main
- [ ] Make repository public

## Notes
- Keep PR numbers (#2, #4, #5, #6) in relevant commits
- Preserve important architectural decisions
- Ensure each commit builds and tests pass