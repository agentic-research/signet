# Revocation System Enhancement TODO

## 🎯 Overview
Track and implement enhancements to the revocation system after completing real cryptographic integration tests (PR #39).

---

## 🧪 Testing Enhancements

### Performance & Load Testing
- [x] Add benchmark tests for revocation checking under load ✅
- [x] Measure cache hit rates and optimization opportunities ✅
- [x] Test with thousands of concurrent requests ✅ (338,906 ops in parallel benchmark)
- [ ] Profile memory usage during high-load scenarios

### Edge Cases & Race Conditions
- [x] Add tests for cache race condition ✅ (singleflight prevents races)
- [x] Test rollback protection with sequence number manipulation ✅
- [x] Add fuzzing for malformed CA bundles and signatures ✅ (1M+ executions, no panics)
  - FuzzCABundleSignatureVerification: 1M+ execs, 237 interesting cases
  - FuzzCABundleMarshaling: 1.2M+ execs, deterministic CBOR encoding verified
  - FuzzTokenRevocationLogic: 671K+ execs, revocation logic validated
- [x] Test defensive copying for the Keys map ✅ (already implemented)
- [ ] Test grace period behavior with PrevKeyID in detail
- [ ] Test token expiry edge cases (just expired, about to expire)
- [ ] Test clock skew handling with various time offsets

---

## 🔒 Security Hardening

### Timing Attack Mitigation
- [x] Implement constant-time comparison for key lookups ✅ (already implemented)
- [x] Use `crypto/subtle.ConstantTimeCompare` where appropriate ✅
- [x] Add timing attack resistance tests ✅ (TestTimingAttack_KeyComparison)

### Memory Safety
- [x] Verify defensive copying is implemented for all shared data structures ✅
- [x] Add tests to ensure Keys map cannot be modified externally ✅ (TestDefensiveCopies_KeysMap)
- [x] Audit for any other potential memory safety issues ✅

### Cryptographic Enhancements
- [ ] Test with different key sizes when supported
- [ ] Plan support for additional algorithms (P-256, RSA)
- [ ] Add tests for algorithm agility

---

## 📚 Documentation

### Architecture Documentation
- [ ] Document the revocation system architecture
- [ ] Create diagrams for two-step verification flow
- [ ] Document CA bundle structure and signing process

### Operational Guides
- [ ] Create runbook for CA bundle rotation procedures
- [ ] Write incident response guide for revocation events
- [ ] Document monitoring and alerting requirements

### Developer Documentation
- [ ] Add examples of integrating revocation checker
- [ ] Document test helper functions for other developers
- [ ] Create troubleshooting guide

---

## 🐛 Bug Fixes & Issues

### From Test Comments
- [x] Fix cache race condition ✅ (singleflight prevents duplicate fetches)
- [ ] Improve storage error handling (TestFirstRequestEdgeCase_StorageFailureVsNotFound)
- [x] Address timing attack vulnerability in key comparison ✅ (already using constant-time)
- [x] Implement proper defensive copies ✅ (Keys map properly copied)

---

## 🚀 Implementation Improvements

### Storage Enhancements
- [ ] Storage.GetLastSeenSeqno should return (seqno, exists, error) triple
- [ ] Add persistent storage backend option (Redis, etcd)
- [ ] Implement storage metrics and monitoring

### Cache Improvements
- [ ] Add cache warming on startup
- [ ] Implement cache invalidation strategies
- [ ] Add cache metrics (hit rate, miss rate, evictions)

---

## 📊 Priority Matrix

### P0 - Critical (Security) ✅ COMPLETED
1. ✅ Timing attack mitigation (constant-time comparisons implemented)
2. ✅ Defensive copying implementation (Keys map properly copied)
3. ✅ Cache race condition fix (singleflight prevents duplicates)

### P1 - Important (Correctness) ✅ MOSTLY COMPLETED
1. 🔄 Storage error handling improvements (TestFirstRequestEdgeCase needs fix)
2. ✅ Rollback protection tests (implemented and passing)
3. ✅ Fuzzing for malformed inputs (3 fuzz tests, 2.8M+ total executions)

### P2 - Nice to Have (Performance) ✅ COMPLETED
1. ✅ Benchmark tests (cache hits: 3.5M ops/sec, parallel: 338K ops/sec)
2. ✅ Cache optimization (verified with benchmarks)
3. ✅ Load testing (concurrent request testing complete)

### P3 - Future (Enhancement)
1. Additional algorithm support
2. Persistent storage backends
3. Advanced monitoring

---

## 📝 Notes

- All tests should use the existing test helpers for consistency
- Security fixes should be prioritized over performance improvements
- Documentation should be updated alongside code changes
- Consider creating separate PRs for each major category
