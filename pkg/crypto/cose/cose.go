// Package cose provides a thin wrapper around a standard COSE library
// to sign and verify Signet tokens.
// We will use a library like 'veraison/go-cose' for the implementation.
package cose

// Signer signs payloads using COSE Sign1
type Signer interface {
	// Sign creates a COSE Sign1 message from the payload
	Sign(payload []byte) ([]byte, error)
}

// Verifier verifies COSE Sign1 messages
type Verifier interface {
	// Verify verifies a COSE Sign1 message and returns the payload
	Verify(coseSign1 []byte) (payload []byte, err error)
}

// NewSigner creates a new COSE signer
// Implementation will wrap external COSE library
func NewSigner(privateKey interface{}, algorithm string) (Signer, error) {
	// Implementation will follow using external library
	return nil, nil
}

// NewVerifier creates a new COSE verifier
// Implementation will wrap external COSE library
func NewVerifier(publicKey interface{}) (Verifier, error) {
	// Implementation will follow using external library
	return nil, nil
}