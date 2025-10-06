# Signet Documentation Cleanup Plan

**Date**: 2025-10-06
**Objective**: Make project status immediately obvious when visiting the repo
**Context**: Signet v0.0.1 alpha, solo-developed, go-cms extracted with NO SECURITY REVIEW

---

## Executive Summary

The Signet documentation suffers from:
1. **Status fragmentation** across 4 overlapping files
2. **Missing security warnings** for go-cms extraction
3. **Point-in-time cruft** (PR reviews, agent logs)
4. **Organizational mismatch** (ADRs for solo project)

This plan consolidates documentation to a single canonical status file (DEVELOPMENT_ROADMAP.md), adds critical security warnings, and removes/reorganizes 13 files for clarity.

---

## Critical Security Gap

**URGENT**: The go-cms library extraction is mentioned but lacks a prominent security warning:

> **github.com/jamestexas/go-cms HAS NOT RECEIVED A SECURITY REVIEW**

This must be added to:
- README.md (Core Libraries table)
- docs/CMS_IMPLEMENTATION.md (top banner)
- DEVELOPMENT_ROADMAP.md (Known Limitations section)

**Risk**: Users may assume extracted library is production-ready. It is NOT.

---

## Analysis Summary

### Current Documentation Landscape

**Total markdown files**: 35

**Categories**:
- **Root-level docs** (8): README, ROADMAP, ARCHITECTURE, SECURITY, etc.
- **Status tracking** (4): README, ROADMAP, IMPLEMENTATION_STATUS, FEATURE_MATRIX - **OVERLAP**
- **Point-in-time** (5): PRODUCTION_READINESS_REPORT, SECURITY_AUDIT, agent logs
- **Technical deep-dives** (4): CMS_IMPLEMENTATION, PERFORMANCE, REVOCATION_INTERFACE, etc.
- **ADRs** (7): docs/adrs/ directory - **MISMATCH** (solo project doesn't need formal ADR process)
- **Package READMEs** (various): pkg/*/README.md files

### Key Issues Identified

1. **Status Fragmentation**:
   - README.md has high-level "What Works Today"
   - DEVELOPMENT_ROADMAP.md has detailed implementation tables (626 lines)
   - docs/IMPLEMENTATION_STATUS.md duplicates ROADMAP content (176 lines)
   - docs/FEATURE_MATRIX.md also overlaps (150 lines)
   - **Result**: Guaranteed drift, confusion about source of truth

2. **Security Warning Gap**:
   - CMS_IMPLEMENTATION.md mentions go-cms extraction
   - README.md links to go-cms
   - **NEITHER warns: "This library has NOT received a security review"**
   - Users may assume it's production-ready (it's not)

3. **Point-in-Time Cruft**:
   - PRODUCTION_READINESS_REPORT.md is PR-specific (Oct 5, 2025)
   - surgical-reviewer logs are work artifacts, not documentation
   - theoretical-foundations-analyst log is analysis scratch work
   - These clutter the repo and suggest outdated information

4. **Organizational Mismatch**:
   - docs/adrs/ suggests formal team ADR process
   - Signet is solo-developed, these are **design documents** not formal decisions
   - "ADR" implies decision record; "design" better reflects solo dev context

5. **README Clarity**:
   - Good status warnings exist
   - Could better point to ROADMAP as canonical source
   - go-cms security warning missing

---

## Detailed Action Plan

### Part 1: DELETE (Cruft Removal)

**Files to delete** (6 total):

1. `/Users/jamesgardner/remotes/jamestexas/signet/surgical-reviewer_2025-10-04_agent_log.md`
   - **Why**: Point-in-time work artifact from agent review
   - **Impact**: None (no references)

2. `/Users/jamesgardner/remotes/jamestexas/signet/surgical-reviewer_2025-10-05_agent_log.md`
   - **Why**: Point-in-time work artifact from agent review
   - **Impact**: None (no references)

3. `/Users/jamesgardner/remotes/jamestexas/signet/docs/analysis/theoretical-foundations-analyst_2025-10-04_agent_log.md`
   - **Why**: Analysis scratch work, not documentation
   - **Impact**: None (no references)

4. `/Users/jamesgardner/remotes/jamestexas/signet/PRODUCTION_READINESS_REPORT.md`
   - **Why**: PR-specific review (Oct 5), security findings tracked in SECURITY_AUDIT.md
   - **Impact**: None (PR is merged, findings captured elsewhere)

5. `/Users/jamesgardner/remotes/jamestexas/signet/docs/IMPLEMENTATION_STATUS.md`
   - **Why**: Redundant with DEVELOPMENT_ROADMAP.md Section 3 (Implementation Gaps)
   - **Impact**: ROADMAP is more detailed and up-to-date, maintaining both guarantees drift
   - **Note**: Check for any unique content before deletion (unlikely)

6. `/Users/jamesgardner/remotes/jamestexas/signet/docs/FEATURE_MATRIX.md`
   - **Why**: Redundant with DEVELOPMENT_ROADMAP.md Section 1 (Current State)
   - **Impact**: ROADMAP has same information plus more detail
   - **Note**: Check for any unique content before deletion (unlikely)

**Additional cleanup** (if docs/analysis/ is now empty):
- Delete `/Users/jamesgardner/remotes/jamestexas/signet/docs/analysis/` directory

---

### Part 2: MOVE (Reorganization)

**Directory rename**:

**FROM**: `/Users/jamesgardner/remotes/jamestexas/signet/docs/adrs/`
**TO**: `/Users/jamesgardner/remotes/jamestexas/signet/docs/design/`

**Rationale**:
- Solo-developed project doesn't need formal "Architecture Decision Record" process
- These are **design documents** that explain technical choices
- "design" better reflects their purpose and solo context
- More approachable naming for contributors

**Files affected** (7 total - all move together):

1. `docs/adrs/ADR-001-signet-tokens.md` → `docs/design/001-signet-tokens.md`
2. `docs/adrs/ADR-002-protocol-spec.md` → `docs/design/002-protocol-spec.md`
3. `docs/adrs/ADR-003-sdk.md` → `docs/design/003-sdk.md`
4. `docs/adrs/ADR-004-bridge-certs-for-federation.md` → `docs/design/004-bridge-certs.md`
5. `docs/adrs/ADR-005-sensitive-data-in-memory.md` → `docs/design/005-memory-security.md`
6. `docs/adrs/ADR-006-revocation-strategy.md` → `docs/design/006-revocation.md`
7. `docs/adrs/http-proof-of-possession.md` → `docs/design/007-http-pop.md`

**Filename simplifications**:
- Remove "ADR-" prefix (implied by location in design/)
- Shorten some names for clarity
- Add 007 number to http-proof-of-possession.md for consistency

**Update references**:
- `git grep -r "docs/adrs"` to find all references
- Update links in:
  - README.md
  - DEVELOPMENT_ROADMAP.md
  - ARCHITECTURE.md
  - Any other docs linking to ADRs

---

### Part 3: UPDATE (Security & Clarity)

#### Update 1: docs/CMS_IMPLEMENTATION.md

**ADD AT TOP** (lines 1-6):

```markdown
# CMS/PKCS#7 Implementation for Ed25519

> **SECURITY WARNING**
> The CMS implementation has been extracted to [github.com/jamestexas/go-cms](https://github.com/jamestexas/go-cms).
> **THIS LIBRARY HAS NOT RECEIVED A SECURITY REVIEW.**
> Use in production environments at your own risk.

## Overview
```

**Current location**: Line 3 (Overview header)
**Impact**: Makes security status immediately clear

---

#### Update 2: README.md

**Section**: Core Libraries table (currently lines 94-99)

**CURRENT**:
```markdown
| Package | Purpose |
|---------|---------|
| [`github.com/jamestexas/go-cms`](https://github.com/jamestexas/go-cms) | Ed25519 CMS/PKCS#7 (standalone library) |
```

**REPLACE WITH**:
```markdown
| Package | Purpose | Security Review |
|---------|---------|-----------------|
| [`github.com/jamestexas/go-cms`](https://github.com/jamestexas/go-cms) | Ed25519 CMS/PKCS#7 (standalone library) | ⚠️ **Not reviewed** |
```

**Additional update** - Section "Why Signet?" (around line 187)

**CURRENT**:
```markdown
**Unique features:**
- First Go library with Ed25519 CMS/PKCS#7 support
```

**REPLACE WITH**:
```markdown
**Unique features:**
- First Go library with Ed25519 CMS/PKCS#7 support (⚠️ [go-cms](https://github.com/jamestexas/go-cms) not security reviewed)
```

---

#### Update 3: DEVELOPMENT_ROADMAP.md

**Section**: Known Limitations (currently lines 38-48)

**CURRENT**:
```markdown
### Known Limitations

**Security (Remaining):**
- ❌ **Revocation system** - Design exploration in progress, implementation pending
- ❌ **4 HIGH severity findings** - Type assertions, mutex protection, key leaks (See SECURITY_AUDIT.md)
- 🚧 **Capability validation logic** - token structure complete, enforcement missing
```

**ADD AFTER LINE 40**:
```markdown
- ⚠️ **go-cms library not reviewed** - Extracted CMS/PKCS#7 implementation lacks security audit
```

---

#### Update 4: SECURITY_AUDIT.md

**ADD AT TOP** (lines 1-5):

```markdown
# Signet Security Audit Report

> **Note**: This is an ongoing audit log documenting security findings as they are discovered.
> For current project status and implementation roadmap, see [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md).

## Audit Metadata
```

**Current location**: Line 1 starts with "# Signet Security Audit Report"
**Impact**: Clarifies this is not the status document, points to canonical source

---

#### Update 5: docs/problem-statement.md (Review for Relevance)

**Action**: Read full file to determine if still relevant

**Options**:
1. **Keep**: If it provides valuable historical context or user problem framing
2. **Archive**: Move to docs/archive/ if outdated but worth preserving
3. **Delete**: If completely superseded by current design docs

**Decision criteria**:
- Does it describe problems that current design solves?
- Is it referenced by other docs?
- Does it provide value to new contributors?

---

### Part 4: UPDATE REFERENCES

After moves and deletions, update all cross-references:

**Files likely needing updates**:
1. README.md - Update ADR links to design/
2. DEVELOPMENT_ROADMAP.md - Update ADR references
3. ARCHITECTURE.md - Update ADR links
4. CLAUDE.md - Update documentation structure if mentioned

**Search commands**:
```bash
# Find ADR references
git grep -n "docs/adrs"

# Find IMPLEMENTATION_STATUS references
git grep -n "IMPLEMENTATION_STATUS"

# Find FEATURE_MATRIX references
git grep -n "FEATURE_MATRIX"

# Find PRODUCTION_READINESS references
git grep -n "PRODUCTION_READINESS"
```

**Update pattern**:
- `docs/adrs/ADR-001` → `docs/design/001-signet-tokens.md`
- `docs/adrs/ADR-002` → `docs/design/002-protocol-spec.md`
- etc.

---

## Expected File Structure After Cleanup

```
/Users/jamesgardner/remotes/jamestexas/signet/
├── README.md                           # ✏️ UPDATED (go-cms warning)
├── DEVELOPMENT_ROADMAP.md              # ✏️ UPDATED (go-cms warning) - CANONICAL STATUS
├── ARCHITECTURE.md                     # (update ADR references)
├── SECURITY.md                         # (unchanged)
├── SECURITY_AUDIT.md                   # ✏️ UPDATED (clarifying note)
├── CONTRIBUTING.md                     # (update ADR references if needed)
├── CHANGELOG.md                        # (unchanged)
├── CLAUDE.md                           # (update doc structure if mentioned)
├── INVESTIGATION_LOG.md                # (gitignored, local only)
├── documentation-synthesis-architect_2025-10-06_agent_log.md  # (this work log)
│
├── docs/
│   ├── design/                         # 📁 RENAMED from adrs/
│   │   ├── 001-signet-tokens.md        # ↔️ MOVED & RENAMED
│   │   ├── 002-protocol-spec.md        # ↔️ MOVED & RENAMED
│   │   ├── 003-sdk.md                  # ↔️ MOVED & RENAMED
│   │   ├── 004-bridge-certs.md         # ↔️ MOVED & RENAMED
│   │   ├── 005-memory-security.md      # ↔️ MOVED & RENAMED
│   │   ├── 006-revocation.md           # ↔️ MOVED & RENAMED
│   │   └── 007-http-pop.md             # ↔️ MOVED & RENAMED
│   │
│   ├── CMS_IMPLEMENTATION.md           # ✏️ UPDATED (security warning)
│   ├── PERFORMANCE.md                  # (unchanged)
│   ├── REVOCATION_INTERFACE.md         # (unchanged)
│   ├── IMPLEMENTATION_SEQUENCE.md      # (unchanged)
│   └── problem-statement.md            # 🔍 REVIEW (keep/archive/delete?)
│
├── pkg/                                # (package READMEs unchanged)
├── cmd/                                # (unchanged)
└── demo/                               # (unchanged)

DELETED:
❌ surgical-reviewer_2025-10-04_agent_log.md
❌ surgical-reviewer_2025-10-05_agent_log.md
❌ docs/analysis/theoretical-foundations-analyst_2025-10-04_agent_log.md
❌ PRODUCTION_READINESS_REPORT.md
❌ docs/IMPLEMENTATION_STATUS.md
❌ docs/FEATURE_MATRIX.md
```

**Legend**:
- ✏️ = Updated (content changes)
- ↔️ = Moved (location change)
- ❌ = Deleted
- 📁 = Directory renamed
- 🔍 = Review needed

---

## Implementation Sequence

**Recommended order** to minimize breakage:

### Step 1: Create Safety Backup
```bash
git checkout -b doc-cleanup
git commit -m "checkpoint: before documentation cleanup"
```

### Step 2: Add Security Warnings (Updates)
1. Update docs/CMS_IMPLEMENTATION.md (add banner)
2. Update README.md (add security column, update unique features)
3. Update DEVELOPMENT_ROADMAP.md (add go-cms limitation)
4. Update SECURITY_AUDIT.md (add clarifying note)
5. Commit: `git commit -m "docs: add go-cms security warnings"`

### Step 3: Review problem-statement.md
```bash
# Read file
less docs/problem-statement.md

# Decision: keep, archive, or delete
# If archive:
mkdir -p docs/archive
git mv docs/problem-statement.md docs/archive/
# If delete:
git rm docs/problem-statement.md
```
Commit if changes made

### Step 4: Move ADR Directory
```bash
# Create new design directory
mkdir -p docs/design

# Move and rename files
git mv docs/adrs/ADR-001-signet-tokens.md docs/design/001-signet-tokens.md
git mv docs/adrs/ADR-002-protocol-spec.md docs/design/002-protocol-spec.md
git mv docs/adrs/ADR-003-sdk.md docs/design/003-sdk.md
git mv docs/adrs/ADR-004-bridge-certs-for-federation.md docs/design/004-bridge-certs.md
git mv docs/adrs/ADR-005-sensitive-data-in-memory.md docs/design/005-memory-security.md
git mv docs/adrs/ADR-006-revocation-strategy.md docs/design/006-revocation.md
git mv docs/adrs/http-proof-of-possession.md docs/design/007-http-pop.md

# Remove old directory
rmdir docs/adrs

git commit -m "docs: reorganize adrs/ to design/ for solo project context"
```

### Step 5: Update Cross-References
```bash
# Find and update references
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-001|docs/design/001-signet-tokens|g'
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-002|docs/design/002-protocol-spec|g'
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-003|docs/design/003-sdk|g'
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-004|docs/design/004-bridge-certs|g'
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-005|docs/design/005-memory-security|g'
git grep -l "docs/adrs" | xargs sed -i.bak 's|docs/adrs/ADR-006|docs/design/006-revocation|g'
git grep -l "docs/adrs/http-proof-of-possession" | xargs sed -i.bak 's|docs/adrs/http-proof-of-possession|docs/design/007-http-pop|g'

# Clean up backup files
find . -name "*.bak" -delete

git add -A
git commit -m "docs: update all cross-references to design/"
```

### Step 6: Delete Redundant Files
```bash
# Delete point-in-time cruft
git rm surgical-reviewer_2025-10-04_agent_log.md
git rm surgical-reviewer_2025-10-05_agent_log.md
git rm docs/analysis/theoretical-foundations-analyst_2025-10-04_agent_log.md
git rm PRODUCTION_READINESS_REPORT.md

# Delete redundant status docs (verify no unique content first)
git rm docs/IMPLEMENTATION_STATUS.md
git rm docs/FEATURE_MATRIX.md

# Clean up empty directory if exists
rmdir docs/analysis 2>/dev/null || true

git commit -m "docs: remove point-in-time reports and redundant status files"
```

### Step 7: Validate & Test
```bash
# Check all markdown files render correctly
make build  # Ensure code still compiles
make test   # Ensure tests pass

# Manually verify:
# - README.md displays correctly
# - DEVELOPMENT_ROADMAP.md is comprehensive
# - All links work (no 404s to deleted files)
# - Security warnings are visible
```

### Step 8: Final Review & Merge
```bash
# Review all changes
git log --oneline main..doc-cleanup

# If satisfied, merge
git checkout main
git merge doc-cleanup
git branch -d doc-cleanup

# Or create PR if preferred
gh pr create --title "Documentation cleanup: consolidate status, add security warnings" \
  --body "See DOCUMENTATION_CLEANUP_PLAN.md for rationale"
```

---

## Success Criteria

Documentation cleanup is **successful** when:

✅ **Single canonical status document**: DEVELOPMENT_ROADMAP.md clearly serves as source of truth
✅ **Security warnings visible**: go-cms extraction prominently noted with NO SECURITY REVIEW
✅ **Clean repository**: No point-in-time cruft (PR reviews, agent logs)
✅ **Logical organization**: docs/design/ better reflects solo project context
✅ **README clarity**: Entry point directs users to ROADMAP for detailed status
✅ **All links work**: No broken references to deleted/moved files
✅ **Build succeeds**: Documentation changes don't break anything
✅ **30-second clarity**: New visitors immediately understand project maturity

---

## Rollback Plan

If cleanup causes issues:

```bash
# If not yet merged
git checkout main
git branch -D doc-cleanup

# If already merged
git revert <merge-commit-sha>

# Or reset to before cleanup
git reset --hard <commit-before-cleanup>
```

**Note**: Backup branch (`doc-cleanup` before merge) provides safety net

---

## Post-Cleanup Maintenance

To prevent documentation drift in the future:

1. **Single Status Source**: Always update DEVELOPMENT_ROADMAP.md for status changes
2. **Security Warnings**: Keep go-cms review status in 3 places (README, ROADMAP, CMS_IMPLEMENTATION)
3. **Design Docs**: Add new design documents to docs/design/ with sequential numbering
4. **No Point-in-Time Docs**: PR reviews and agent logs stay in branches, not main
5. **Link Validation**: Periodically check for broken links with `markdown-link-check`

---

## Appendix: Content Map

### Files That Track Status (Before Cleanup)

| File | Lines | Content | Keep? |
|------|-------|---------|-------|
| README.md | 206 | High-level "What Works Today" | ✅ Keep (entry point) |
| DEVELOPMENT_ROADMAP.md | 626 | Detailed implementation tables, phases, timeline | ✅ CANONICAL |
| docs/IMPLEMENTATION_STATUS.md | 176 | Component status table, quick start | ❌ DELETE (redundant) |
| docs/FEATURE_MATRIX.md | 150 | Feature comparison, roadmap vision | ❌ DELETE (redundant) |

**Analysis**: ROADMAP has all information from IMPLEMENTATION_STATUS and FEATURE_MATRIX, plus more detail. No unique content would be lost.

### go-cms References (Before Cleanup)

| File | Line | Current Text | Needs Warning? |
|------|------|--------------|----------------|
| README.md | 95 | `github.com/jamestexas/go-cms` Ed25519 CMS/PKCS#7 | ✅ YES |
| README.md | 188 | First Go library with Ed25519 CMS/PKCS#7 support | ✅ YES |
| docs/CMS_IMPLEMENTATION.md | 171 | Repository: github.com/jamestexas/go-cms | ✅ YES (banner) |
| DEVELOPMENT_ROADMAP.md | - | (not mentioned) | ✅ YES (add to limitations) |

---

## Questions & Answers

**Q: Why delete PRODUCTION_READINESS_REPORT.md instead of archiving?**
A: PR-specific content has no long-term value. Security findings are tracked in SECURITY_AUDIT.md. No unique insights to preserve.

**Q: Why rename "adrs" to "design"?**
A: ADRs (Architecture Decision Records) imply a formal team decision-making process. Solo projects don't have that process - these are design documents explaining technical choices. "design" is more accurate and approachable.

**Q: What if IMPLEMENTATION_STATUS.md has unique content?**
A: Review before deletion. Diff against DEVELOPMENT_ROADMAP.md. If unique insights found, merge them into ROADMAP first, then delete.

**Q: Should agent logs be gitignored?**
A: Yes. Add to .gitignore:
```
*_agent_log.md
documentation-synthesis-architect_*.md
```

**Q: What about the current work log (this plan's log)?**
A: Keep as artifact of this cleanup. Future agent logs should be gitignored.

---

## Document Metadata

**Created**: 2025-10-06
**Author**: Documentation Synthesis Architect (Claude Code)
**Work Log**: documentation-synthesis-architect_2025-10-06_agent_log.md
**Estimated Effort**: 2-3 hours
**Risk**: LOW (documentation-only changes, no code affected)
