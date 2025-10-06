# Sensitive Data Handling in Memory

## Status

Proposed

## Context

The migration process from a file-based master key to a secure OS keyring involves reading the key from a PEM file, hex-encoding it, and storing it in the keyring. The `go-keyring` library used for this purpose requires the secret to be passed as a `string`.

In Go, converting a byte slice to a string (e.g., `string(myBytes)`) creates an immutable copy of the data. This means that even if the original byte slice is zeroized, the string copy remains in memory until it is garbage-collected. This leaves sensitive key material in memory for an indeterminate amount of time.

## Decision

We will acknowledge this limitation and document it clearly. The `go-keyring` library is a widely used and respected library, and its API is what we must work with.

We will take the following actions:

1. Add package-level documentation to the `keystore` package to highlight this limitation.
2. Continue to zeroize all byte slices that contain sensitive data at the earliest possible opportunity.
3. Investigate alternative keyring libraries that may accept `[]byte` directly in the future.

## Consequences

- **Positive**:
  - The limitation is clearly documented, and developers are aware of it.
- **Negative**:
  - Sensitive key material may remain in memory longer than desired.
- **Neutral**:
  - The security posture is not degraded from the current state, but a potential improvement is deferred.
