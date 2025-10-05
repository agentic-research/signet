# Agent 1: SIG1 Wire Format Integration

## Your Mission
You are Agent 1, responsible for integrating the SIG1 wire format throughout the Signet codebase. The SIG1 format is already fully implemented - your job is to wire it up everywhere.

## Context
- **Worktree**: `/Users/jamesgardner/remotes/jamestexas/signet-sig1`
- **Branch**: `feature/sig1-wire-format`
- **Timeline**: 1 week
- **Files to reference**:
  - `IMPLEMENTATION.md` - Your detailed implementation plan
  - `SECURITY_AUDIT.md` - Security findings you must address

## Critical Security Fixes Required

### Finding #26: Token ID Truncation (MEDIUM)
**Location**: `pkg/http/middleware/signet.go:93`
```go
// CURRENT (BAD):
tokenID := hex.EncodeToString(proof.JTI[:min(8, len(proof.JTI))])

// FIX: Use full JTI
tokenID := hex.EncodeToString(proof.JTI)
```
**Why**: 8-byte truncation can cause token ID collisions. Use the full 16-byte JTI.

### Finding #28: No Request Size Limits (LOW)
**Location**: `pkg/http/middleware/signet.go:139`
```go
// Add before building canonical request:
const maxRequestSize = 1 * 1024 * 1024 // 1MB
if r.ContentLength > maxRequestSize {
    return ErrRequestTooLarge
}
```
**Why**: Prevents DoS via memory exhaustion with large requests.

## Your Tasks

### Phase 1: Fix Security Issues (Do This First!)
1. ✅ Fix token ID truncation in middleware
2. ✅ Add request size limits
3. ✅ Run tests to ensure no regressions

### Phase 2: Update Demo Server
Replace raw CBOR token issuance with SIG1 format in `demo/http-auth/server/main.go`:
```go
// Import
import "github.com/jamestexas/signet/pkg/crypto/cose"

// In issueTokenHandler:
ephemeralSigner, _ := cose.NewEd25519Signer(ephemeralPriv)
defer ephemeralSigner.Destroy()

sig1Wire, err := signet.EncodeSIG1(token, ephemeralSigner)
response["token"] = sig1Wire  // Instead of base64(cbor)
```

### Phase 3: Update Demo Client
Parse SIG1 format in `demo/http-auth/client/main.go`:
```go
// In requestToken:
sig1, err := signet.DecodeSIG1(response.Token)
if err != nil {
    return nil, fmt.Errorf("failed to parse SIG1: %w", err)
}
token := sig1.Token

// Verify COSE signature
verifier, _ := cose.NewEd25519Verifier(masterPublicKey)
payload, err := verifier.Verify(sig1.Signature)
// ... validate payload matches token
```

### Phase 4: Update Middleware
Add SIG1 support to Authorization header parsing:
```go
// In ServeHTTP:
authHeader := r.Header.Get("Authorization")
if strings.HasPrefix(authHeader, "Bearer SIG1.") {
    sig1, err := signet.DecodeSIG1(strings.TrimPrefix(authHeader, "Bearer "))
    // Verify COSE signature
    // Extract token for existing processing
}
```

### Phase 5: Testing
```bash
# Run all tests
make test

# Test demo end-to-end
cd demo/http-auth && docker-compose up --build

# Verify SIG1 format
curl -v http://localhost:8080/issue-token | jq .token
# Should start with "SIG1."
```

## Success Criteria
- [ ] Finding #26 fixed: Full JTI used, no truncation
- [ ] Finding #28 fixed: Request size limits implemented
- [ ] Demo server issues SIG1 format tokens
- [ ] Demo client parses and verifies SIG1 tokens
- [ ] Middleware accepts SIG1 in Authorization header
- [ ] All tests pass
- [ ] Integration test demonstrates full SIG1 flow

## Commands You'll Need
```bash
# Build and test
make build test

# Run demos
cd demo/http-auth
docker-compose up --build

# Check for security issues
gosec ./pkg/http/middleware/...

# Create PR when done
git add -A
git commit -m "feat: integrate SIG1 wire format and fix security findings #26 #28"
git push -u origin feature/sig1-wire-format
```

## Key Files to Modify
- `pkg/http/middleware/signet.go` - Fix truncation, add size limits, SIG1 support
- `demo/http-auth/server/main.go` - Issue SIG1 tokens
- `demo/http-auth/client/main.go` - Parse SIG1 tokens
- `pkg/http/middleware/interfaces.go` - Update TokenRecord if needed

## Questions? Check These First
1. SIG1 format spec: `pkg/signet/sig1.go`
2. COSE signing: `pkg/crypto/cose/cose.go`
3. Security issues: `SECURITY_AUDIT.md`
4. Implementation plan: `IMPLEMENTATION.md`

**Remember**: Fix the security findings FIRST, then integrate SIG1. The format is already implemented - you just need to use it!
