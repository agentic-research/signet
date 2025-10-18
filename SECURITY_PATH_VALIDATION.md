# Path Traversal Security Improvements

## Summary

This document describes the comprehensive path traversal security fixes implemented to address critical vulnerabilities in the home directory validation logic.

## Vulnerabilities Addressed

### 1. Incomplete System Path Blacklist ✅ FIXED

**Previous Issue**: The blacklist was missing critical system directories:
- `/tmp` - World-writable, allows privilege escalation
- `/dev` - Device files, dangerous for I/O operations
- `/boot` - Boot partition, critical system files
- `/lib`, `/lib64`, `/lib32` - System libraries
- `/opt`, `/root`, `/mnt`, `/media`, `/srv` - Other sensitive directories

**Fix**: Expanded blacklist to include all sensitive system directories.

### 2. TOCTOU (Time-of-Check-Time-of-Use) Race Condition ✅ FIXED

**Previous Issue**: Path validation only occurred at flag parsing time, allowing an attacker to:
1. Provide a safe path that passes validation
2. Replace the path with a symlink to `/etc` after validation
3. Application would then write to `/etc` instead of intended directory

**Fix**: Added `ValidateHomePathRuntime()` function for runtime validation before each use.

### 3. Windows System Paths Not Validated ✅ FIXED

**Previous Issue**: No validation of Windows system directories.

**Fix**: Added comprehensive Windows path validation:
- `C:\Windows` and subdirectories
- `C:\Program Files` and `C:\Program Files (x86)`
- `C:\ProgramData`
- `C:\Windows\Temp`
- `C:\$Recycle.Bin`
- `C:\System Volume Information`

### 4. Nested Symlink Attacks ✅ FIXED

**Previous Issue**: Only single-level symlinks were resolved.

**Fix**: `filepath.EvalSymlinks()` now resolves entire symlink chains recursively.

## Implementation Details

### New Functions

#### `getSystemPaths() []string`
Returns comprehensive list of blocked system paths for both Unix-like and Windows systems.

#### `isSystemPath(path string, systemPaths []string) bool`
Checks if a path is within any system directory with:
- Exact match checking
- Proper path separator handling to avoid false positives
- Case-insensitive comparison on Windows

#### `ValidateHomePathRuntime(path string) error`
Runtime validation to prevent TOCTOU attacks. Should be called before any operation that uses the home directory.

### Testing Strategy

Comprehensive TDD approach with tests for:
- All system paths (existing and newly added)
- Single and nested symlink attacks
- TOCTOU race condition scenarios
- Windows-specific paths
- Valid user directory access

## Security Best Practices

1. **Defense in Depth**: Multiple layers of validation (parse-time and runtime)
2. **Fail Secure**: Reject suspicious paths rather than trying to sanitize
3. **Comprehensive Blacklist**: Block all known system directories
4. **Platform-Specific**: Handle both Unix-like and Windows systems
5. **Symlink Resolution**: Recursively resolve all symlinks

## Usage Guidelines

### For Developers

When adding new file operations that use the home directory:

```go
// Always validate at runtime before use
if err := ValidateHomePathRuntime(homeDir); err != nil {
    return fmt.Errorf("invalid home directory: %w", err)
}

// Now safe to use homeDir for operations
file, err := os.Create(filepath.Join(homeDir, "config.json"))
```

### For Security Reviewers

Key areas to audit:
1. All uses of `homeDir` variable should have runtime validation
2. New system paths should be added to `getSystemPaths()`
3. Symlink handling in any new path operations
4. TOCTOU windows between validation and use

## Testing

Run security tests:
```bash
# Run all path validation tests
go test -v ./cmd/signet -run "TestValidateHomeDir|TestSymlinkAttacks|TestTOCTOUAttack"

# Full test suite
go test ./cmd/signet/...
```

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
