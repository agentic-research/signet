# SIG1 Wire Format Integration

**Branch:** `feature/sig1-wire-format`
**Timeline:** 1 week
**Difficulty:** Low (mechanical changes)
**Dependencies:** None

## Security Findings to Address

From SECURITY_AUDIT.md (see file in this directory):
- **Finding #26**: Token ID truncation to 8 bytes may cause collisions (pkg/http/middleware/signet.go:93)
- **Finding #28**: Missing request size limits - potential DoS vector (pkg/http/middleware/signet.go:139)
- **Action Required**: Implement full JTI for unique token identification and add request size validation

## Objective
Replace raw CBOR token passing with the SIG1 wire format throughout the codebase while addressing security findings.

## Current State
- ✅ SIG1 format fully implemented in `pkg/signet/sig1.go`
- ✅ Functions: `EncodeSIG1()`, `DecodeSIG1()`, `VerifySIG1()`
- ❌ Demos use raw CBOR (base64 encoded)
- ❌ Middleware expects raw tokens
- ❌ Clients send raw tokens

## Implementation Plan

### Phase 1: Update Demo Server (Day 1-2)
```go
// demo/http-auth/server/main.go
// BEFORE:
tokenBytes, _ := token.Marshal()
response["token"] = base64.RawURLEncoding.EncodeToString(tokenBytes)

// AFTER:
signer := cose.NewEd25519Signer(ephemeralPriv)
sig1Wire, _ := signet.EncodeSIG1(token, signer)
response["token"] = sig1Wire
```

**Files to modify:**
- [ ] `demo/http-auth/server/main.go` - Issue SIG1 format
- [ ] Store both token and signature in TokenRegistry

### Phase 2: Update Demo Client (Day 2-3)
```go
// demo/http-auth/client/main.go
// BEFORE:
tokenBytes, _ := base64.RawURLEncoding.DecodeString(response.Token)
token, _ := signet.Unmarshal(tokenBytes)

// AFTER:
sig1, _ := signet.DecodeSIG1(response.Token)
token := sig1.Token
// Verify signature with server's public key
```

**Files to modify:**
- [ ] `demo/http-auth/client/main.go` - Parse SIG1 format
- [ ] Update proof generation to use SIG1 components

### Phase 3: Update Middleware (Day 3-4)
```go
// pkg/http/middleware/signet.go
// Add SIG1 support to token extraction
authHeader := r.Header.Get("Authorization")
if strings.HasPrefix(authHeader, "Bearer SIG1.") {
    sig1, err := signet.DecodeSIG1(authHeader[7:])
    // Verify COSE signature
    // Extract token for processing
}
```

**Files to modify:**
- [ ] `pkg/http/middleware/signet.go` - Support SIG1 in Authorization header
- [ ] `pkg/http/middleware/interfaces.go` - Update TokenRecord to include signature
- [ ] `pkg/http/middleware/memory.go` - Store signature with token

### Phase 4: Update Tests (Day 4-5)
- [ ] Add SIG1 format tests to `demo/http-auth/`
- [ ] Update middleware tests for SIG1 parsing
- [ ] Add integration test for full SIG1 flow

### Phase 5: Documentation (Day 5)
- [ ] Update README examples to show SIG1 format
- [ ] Add migration guide from raw CBOR to SIG1
- [ ] Update API documentation

## Success Criteria
1. Demo server issues tokens in SIG1 format
2. Demo client parses and verifies SIG1 tokens
3. Middleware accepts both formats (backwards compatibility)
4. All existing tests pass
5. New SIG1-specific tests pass

## Testing Plan
```bash
# Run existing tests to ensure no regression
make test

# Test demo end-to-end
cd demo/http-auth
docker-compose up --build

# Test middleware with SIG1 tokens
go test ./pkg/http/middleware/... -v

# Integration test
./scripts/testing/test_sig1_integration.sh  # Create this
```

## Rollback Plan
Since SIG1 is already implemented and tested in isolation, the risk is low. If issues arise:
1. Keep raw CBOR as fallback format
2. Add feature flag for SIG1 enablement
3. Support both formats during transition period

## Notes
- SIG1 format is: `SIG1.<base64url(CBOR)>.<base64url(COSE_Sign1)>`
- COSE Sign1 provides signature over the CBOR payload
- This change improves security by ensuring token integrity
- Backwards compatibility should be maintained for 1-2 releases
