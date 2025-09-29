# HTTP Middleware v1.0 Security Hardening

## Wire Format BNF (Updated)

```bnf
signet-proof-header = version ";" mode-spec ";" proof-params
version             = "v1"
mode-spec          = "m=" mode-value
mode-value         = "full" / "compact"  ; full=SIG1 token, compact=ephemeral only

; Full mode (when Authorization header absent)
full-params        = "t=" base64url-sig1-token ";" common-params

; Compact mode (migration phase with existing bearer)
compact-params     = "t=" base64url-cbor ";" "p=" base64url-proof ";"
                     "k=" base64url-keyhash ";" common-params

common-params      = "jti=" base64url-16bytes ";"
                     "cap=" base64url-16bytes ";"
                     "s=" base64url-signature ";"
                     "n=" base64url-16bytes ";"
                     "ts=" unix-timestamp ";"
                     ["crit=" critical-fields ";"]
                     ["bd=" base64url-blake3 ";"]  ; body digest for POST/PUT

base64url-keyhash  = base64url(blake3(jti || ephemeral_public_key))  ; 32 bytes
critical-fields    = field *("," field)  ; must-understand extensions
```

## Interface Changes

```go
// EpochChecker - MUST be called before signature verification
type EpochChecker interface {
    // Returns epoch state and whether token is revoked
    CheckEpoch(ctx context.Context, capID []byte, capVer uint32) (EpochState, error)
}

type EpochState struct {
    MajorEpoch uint32
    MinorEpoch uint32
    Revoked    bool
    Stale      bool  // CDN fetch failed, using cached
}

// VerifierOptions - Updated with new requirements
type VerifierOptions struct {
    MasterKeyStore MasterKeyStore
    Purpose        string
    EpochChecker   EpochChecker     // REQUIRED
    ClockSkew      time.Duration    // Max 60s per ADR-002
    MinClockSkew   time.Duration    // Configurable minimum (10s for high-assurance)
    NonceCache     NonceCache       // Must use jti||nonce key
    MonotonicCheck bool             // Enable ts ≥ lastSeenTS[jti] + 1
}

// NonceCache - Updated interface for jti-scoped nonces
type NonceCache interface {
    // CheckAndStore uses composite key: jti||nonce
    CheckAndStore(jti, nonce []byte, ts int64) error
    // GetLastTimestamp for monotonic check
    GetLastTimestamp(jti []byte) (int64, bool)
}

// ProverOptions - Updated for pre-computation
type ProverOptions struct {
    MasterSigner   crypto.Signer
    IssuerID       string
    Purpose        string
    Validity       time.Duration
    PrecomputeKeys int              // Number of ephemeral keys to pre-generate
}

// Prover interface additions
type Prover interface {
    // Precompute generates ephemeral keys in background
    Precompute(n int) error
    // Metrics for monitoring
    GetCacheStats() ProofCacheStats
}

// Updated ProofHeader with new fields
type ProofHeader struct {
    Version          string
    Mode             string              // "full" or "compact"
    Token            []byte              // Full SIG1 token (full mode) or CBOR (compact)
    JTI              []byte              // Token ID (16 bytes)
    CapabilityID     []byte              // Capability hash (16 bytes)
    EphemeralKeyHash []byte              // Privacy-preserving kid
    EphemeralProof   *epr.EphemeralProof
    RequestSignature []byte
    Nonce            []byte
    Timestamp        int64
    BodyDigest       []byte              // Blake3 of request body
    Critical         []string            // Must-understand fields
}
```

## Security Mitigations

| Gap | Attack Vector | Mitigation | Impact |
|-----|--------------|------------|--------|
| a. Wire format | Token/proof confusion | `m=` mode flag | Prevents downgrade attacks |
| b. Replay scope | Cross-token replay | `jti\|\|nonce` cache key | Isolates replay domains |
| c. Clock skew | Temporal bypass | 60s limit + monotonic check | Prevents clock manipulation |
| d. Revocation | Stale epochs | `EpochChecker` + 410 Gone | Immediate revocation |
| e. Privacy | Key correlation | `H(jti\|\|key)` as kid | Unlinkable requests |
| f. Forward compat | Breaking changes | Ignore unknown + `crit=` | Safe evolution |
| g. Cache DOS | Memory exhaustion | Ristretto + singleflight | Bounded memory |
| h. Body swap | Request tampering | Blake3 digest binding | Integrity protection |
| i. Timing leaks | Signature oracle | `subtle.ConstantTimeCompare` | No timing channels |
| j. Error oracle | Failure analysis | Uniform 401 response | No information leakage |

## Performance Targets

- First request latency: <5ms (with precomputed ephemeral keys)
- Steady-state verification: <500μs
- Cache memory: O(1) with 100K entry limit
- Epoch sync: 50ms P99 (CDN-backed)
- Key rotation: Zero-downtime via inotify