// Package cms implements CMS/PKCS#7 signature verification with Ed25519 support.
//
// This package provides RFC 5652 compliant verification of CMS/PKCS#7 signatures
// using Ed25519 keys, which is unique among Go CMS implementations.
//
// Example usage:
//
//	// Read CMS signature and data
//	cmsData, _ := os.ReadFile("signature.p7s")
//	originalData, _ := os.ReadFile("document.txt")
//
//	// Setup verification options
//	opts := cms.VerifyOptions{
//		Roots: systemRootPool, // Optional: uses system roots if nil
//	}
//
//	// Verify the signature
//	chain, err := cms.Verify(cmsData, originalData, opts)
//	if err != nil {
//		log.Fatal("Verification failed:", err)
//	}
//
//	// The first certificate is the signer
//	signerCert := chain[0]
//	fmt.Printf("Signed by: %s\n", signerCert.Subject)
package cms

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	signetErrors "github.com/jamestexas/signet/pkg/errors"
)

// Object Identifiers for weak algorithms that should be rejected
var (
	oidMD5  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// ASN.1 structures for CMS/PKCS#7 parsing
// These match the structures used internally in signer.go

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue // Can be issuerAndSerialNumber or subjectKeyIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

// VerifyOptions allows specifying verification parameters
type VerifyOptions struct {
	Roots         *x509.CertPool     // Trusted root certificates
	Intermediates *x509.CertPool     // Intermediate certificates
	CurrentTime   time.Time          // Time for validation (default: time.Now())
	TimeFunc      func() time.Time   // Optional time source for testing (overrides CurrentTime)
	KeyUsages     []x509.ExtKeyUsage // Required key usages
}

// Verify parses and validates a detached CMS/PKCS#7 signature
//
// This function implements RFC 5652 (CMS) verification for Ed25519 signatures.
// It validates the signature structure, certificate chain, message digest,
// and cryptographic signature.
//
// Parameters:
//   - cmsSignature: DER-encoded CMS/PKCS#7 signature
//   - detachedData: The original data that was signed
//   - opts: Verification options including trusted roots
//
// Returns:
//   - The validated certificate chain (signer cert first, then intermediates)
//   - An error if verification fails at any step
func Verify(cmsSignature, detachedData []byte, opts VerifyOptions) ([]*x509.Certificate, error) {
	// Step 1: Parse ContentInfo
	var ci contentInfo
	rest, err := asn1.Unmarshal(cmsSignature, &ci)
	if err != nil {
		return nil, signetErrors.NewValidationError("ContentInfo", "", "failed to parse", err)
	}
	if len(rest) > 0 {
		return nil, signetErrors.NewValidationError("ContentInfo", "", "trailing data after CMS structure", nil)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, signetErrors.NewValidationError("ContentType", ci.ContentType.String(),
			"expected SignedData OID", nil)
	}

	// Step 2: Parse SignedData from EXPLICIT [0] content
	if ci.Content.Tag != 0 || ci.Content.Class != 2 || !ci.Content.IsCompound {
		return nil, signetErrors.NewValidationError("Content", "",
			"invalid EXPLICIT tag", nil)
	}

	var sd signedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, signetErrors.NewValidationError("SignedData", "", "failed to parse", err)
	}
	if len(rest) > 0 {
		return nil, signetErrors.NewValidationError("SignedData", "", "trailing data", nil)
	}

	// Step 3: Validate structure
	// Check SignedData version (RFC 5652: should be 1 for issuerAndSerialNumber)
	if sd.Version != 1 {
		return nil, signetErrors.NewValidationError("SignedData.Version",
			fmt.Sprintf("%d", sd.Version), "expected version 1 (issuerAndSerialNumber)", nil)
	}

	// Check and validate all digest algorithms (reject weak algorithms)
	for _, alg := range sd.DigestAlgorithms {
		if alg.Algorithm.Equal(oidMD5) {
			return nil, signetErrors.NewValidationError("DigestAlgorithm",
				"MD5", "weak algorithm not supported", nil)
		}
		if alg.Algorithm.Equal(oidSHA1) {
			return nil, signetErrors.NewValidationError("DigestAlgorithm",
				"SHA-1", "weak algorithm not supported", nil)
		}
		// Only SHA-256 is currently supported
		if !alg.Algorithm.Equal(oidSHA256) {
			return nil, signetErrors.NewValidationError("DigestAlgorithm",
				alg.Algorithm.String(), "only SHA-256 is supported", nil)
		}
	}

	// Check for zero signers
	if len(sd.SignerInfos) == 0 {
		return nil, signetErrors.NewValidationError("SignerInfos", "0", "expected exactly 1", nil)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, signetErrors.NewValidationError("SignerInfos",
			fmt.Sprintf("%d", len(sd.SignerInfos)), "expected exactly 1", nil)
	}
	si := sd.SignerInfos[0]

	// Verify digest algorithm
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, signetErrors.NewValidationError("DigestAlgorithm",
			si.DigestAlgorithm.Algorithm.String(), "expected SHA-256", nil)
	}

	// Verify signature algorithm
	if !si.SignatureAlgorithm.Algorithm.Equal(oidEd25519) {
		return nil, signetErrors.NewValidationError("SignatureAlgorithm",
			si.SignatureAlgorithm.Algorithm.String(), "expected Ed25519", nil)
	}

	// Step 4: Validate and extract certificate
	if len(sd.Certificates.FullBytes) == 0 {
		return nil, signetErrors.NewValidationError("Certificates", "",
			"no certificates found", nil)
	}

	// The certificates field is an IMPLICIT [0] containing the certificate bytes
	if sd.Certificates.FullBytes[0] != 0xA0 {
		return nil, signetErrors.NewValidationError("Certificates", "",
			"invalid IMPLICIT [0] tag", nil)
	}

	// Extract certificate bytes from IMPLICIT [0] field
	certBytes := unwrapContext0(sd.Certificates.FullBytes)
	if certBytes == nil {
		return nil, signetErrors.NewValidationError("Certificates", "",
			"failed to extract certificate content", nil)
	}

	// Parse certificates using proper ASN.1 unmarshaling
	var allCerts []*x509.Certificate
	var signerCert *x509.Certificate

	// Check if this is a SET OF certificates (standard format)
	if len(certBytes) > 0 && certBytes[0] == 0x31 {
		// Extract content from the SET wrapper
		setContent := extractSetContent(certBytes)
		if setContent == nil {
			return nil, signetErrors.NewValidationError("Certificates", "",
				"failed to extract SET content", nil)
		}

		// Try to parse as multiple certificates in the SET
		remaining := setContent
		for len(remaining) > 0 {
			// Try to parse a certificate from the remaining bytes
			var rawCert asn1.RawValue
			rest, err := asn1.Unmarshal(remaining, &rawCert)
			if err != nil {
				// If ASN.1 parsing fails, try direct certificate parsing
				// (some implementations put a single certificate directly in the SET)
				parsedCert, err := x509.ParseCertificate(remaining)
				if err == nil {
					allCerts = append(allCerts, parsedCert)
					if matchesSID(si.SID, parsedCert) {
						signerCert = parsedCert
					}
				}
				break
			}

			// Parse the certificate
			parsedCert, err := x509.ParseCertificate(rawCert.FullBytes)
			if err != nil {
				// Skip malformed certificates but continue processing
				remaining = rest
				continue
			}
			allCerts = append(allCerts, parsedCert)

			// Check if this certificate matches the SignerIdentifier
			if matchesSID(si.SID, parsedCert) {
				signerCert = parsedCert
			}

			remaining = rest
		}

		if len(allCerts) == 0 {
			return nil, signetErrors.NewValidationError("Certificates", "",
				"no valid certificates found in SET", nil)
		}
	} else {
		// Try to parse as a single certificate (backward compatibility with older signer.go)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, signetErrors.NewValidationError("Certificates", "",
				"failed to parse certificate", err)
		}
		allCerts = append(allCerts, cert)
		if matchesSID(si.SID, cert) {
			signerCert = cert
		}
	}

	if signerCert == nil {
		return nil, signetErrors.NewValidationError("Certificate", "",
			"no certificate matches SignerIdentifier", nil)
	}

	// Step 5: Match SignerIdentifier to certificate (already verified above)

	// Step 6: Always validate certificate chain
	// If opts.Roots is nil, the system's default roots will be used
	// Add any additional certificates from the CMS as intermediates
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots, // If nil, system roots will be used
		Intermediates: opts.Intermediates,
		CurrentTime:   opts.CurrentTime,
	}

	// Add non-signer certificates as potential intermediates
	if verifyOpts.Intermediates == nil {
		verifyOpts.Intermediates = x509.NewCertPool()
	}
	for _, c := range allCerts {
		if c != signerCert {
			verifyOpts.Intermediates.AddCert(c)
		}
	}
	// Only set KeyUsages if explicitly provided
	if len(opts.KeyUsages) > 0 {
		verifyOpts.KeyUsages = opts.KeyUsages
	}
	// Use TimeFunc if provided, otherwise CurrentTime, otherwise time.Now()
	if opts.TimeFunc != nil {
		verifyOpts.CurrentTime = opts.TimeFunc()
	} else if verifyOpts.CurrentTime.IsZero() {
		verifyOpts.CurrentTime = time.Now()
	}

	// NOTE: Certificate revocation checking (CRL/OCSP) is intentionally not performed here.
	// Signet follows an offline-first design principle where:
	// - Short-lived certificates (5 minutes) minimize the window for compromised keys
	// - Epoch-based revocation happens at the token level (see ADR-001)
	// - Network dependencies would break offline operation
	// If certificate revocation is critical for your use case, implement it at the CA level
	// or use the VerifyOptions hooks to add custom revocation checking.
	chains, err := signerCert.Verify(verifyOpts)
	if err != nil {
		// Include certificate details for debugging
		certInfo := fmt.Sprintf("subject=%s, serial=%s", signerCert.Subject, signerCert.SerialNumber)
		return nil, signetErrors.NewValidationError("certificate", certInfo,
			fmt.Sprintf("chain validation failed: %v", err), err)
	}

	// Step 7: Verify message digest (if SignedAttrs present)
	if len(si.SignedAttrs.FullBytes) > 0 {
		// Parse signed attributes
		attrs, err := parseSignedAttributes(si.SignedAttrs.FullBytes)
		if err != nil {
			return nil, signetErrors.NewValidationError("SignedAttributes", "",
				"failed to parse", err)
		}

		// Find and verify message digest
		var messageDigest []byte
		var foundDigest bool
		for _, attr := range attrs {
			if attr.Type.Equal(oidAttributeMessageDigest) {
				messageDigest, err = extractDigestFromAttribute(attr.Value)
				if err != nil {
					return nil, signetErrors.NewValidationError("MessageDigest", "",
						"failed to extract", err)
				}
				foundDigest = true
				break
			}
		}

		if !foundDigest {
			return nil, signetErrors.NewValidationError("MessageDigest", "",
				"attribute not found in SignedAttributes", nil)
		}

		// Calculate expected digest
		h := sha256.Sum256(detachedData)

		// Constant-time comparison for defense in depth
		// Note: This is not strictly necessary for comparing public digests,
		// but we keep it for consistency and defensive programming
		if subtle.ConstantTimeCompare(messageDigest, h[:]) != 1 {
			return nil, signetErrors.NewSignatureError("cms",
				"message digest mismatch", nil)
		}
	}

	// Step 8: Reconstruct data for signature verification
	var dataToVerify []byte

	if len(si.SignedAttrs.FullBytes) > 0 {
		// CRITICAL: Reconstruct the SET OF that was signed
		// SignedAttrs is stored as IMPLICIT [0]: A0 <len> <content>
		// But the signature was calculated over: 31 <len> <content>

		// Extract content from IMPLICIT [0] (skip tag and length)
		content := unwrapContext0(si.SignedAttrs.FullBytes)
		if content == nil {
			return nil, signetErrors.NewValidationError("SignedAttributes", "",
				"failed to extract content from IMPLICIT tag", nil)
		}

		// Re-wrap with SET OF tag (0x31) for verification
		dataToVerify = wrapAsSet(content)
	} else {
		// No SignedAttrs: signature is over content hash directly
		h := sha256.Sum256(detachedData)
		dataToVerify = h[:]
	}

	// Step 9: Verify Ed25519 signature
	pubKey, ok := signerCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, signetErrors.NewKeyError("verify", "public",
			fmt.Errorf("expected Ed25519 key, got %T", signerCert.PublicKey))
	}

	if !ed25519.Verify(pubKey, dataToVerify, si.Signature) {
		return nil, signetErrors.NewSignatureError("cms",
			"Ed25519 verification failed", nil)
	}

	// Build the certificate chain with signer cert first
	var certChain []*x509.Certificate
	certChain = append(certChain, signerCert)

	// Add any chain certificates returned from Verify (if available)
	// Take the first chain if multiple are found
	if len(chains) > 0 && len(chains[0]) > 1 {
		// Skip the first cert as it's the signer cert we already added
		certChain = append(certChain, chains[0][1:]...)
	}

	return certChain, nil
}

// Helper Functions

// parseASN1Length parses ASN.1 DER/BER length encoding from data starting at offset
// Returns the length value and new position after length bytes, or error if invalid
// This function properly validates bounds to prevent panics from malformed input
func parseASN1Length(data []byte, offset int) (length int, newPos int, err error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
	}

	pos := offset
	firstByte := data[pos]

	if firstByte < 0x80 {
		// Short form: length is in single byte (0-127)
		length = int(firstByte)
		newPos = pos + 1
	} else if firstByte == 0x80 {
		// Indefinite length - not supported in DER
		return 0, 0, fmt.Errorf("indefinite length encoding not supported")
	} else {
		// Long form: firstByte & 0x7f tells us number of length bytes
		numBytes := int(firstByte & 0x7f)
		if numBytes > 4 {
			// We don't support lengths requiring more than 4 bytes (>4GB)
			return 0, 0, fmt.Errorf("length encoding with %d bytes not supported", numBytes)
		}

		pos++
		if len(data) < pos+numBytes {
			return 0, 0, fmt.Errorf("insufficient data for %d-byte length: need %d, have %d",
				numBytes, pos+numBytes, len(data))
		}

		// Parse the length value
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos+i])
		}
		newPos = pos + numBytes
	}

	// Critical: Validate length doesn't exceed remaining data
	if newPos+length > len(data) {
		return 0, 0, fmt.Errorf("length %d exceeds remaining data %d", length, len(data)-newPos)
	}

	return length, newPos, nil
}

// extractSetContent extracts content from a SET (tag 0x31)
// by skipping the tag and length bytes to get the raw content
func extractSetContent(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Verify SET tag (0x31)
	if data[0] != 0x31 {
		return nil
	}

	// Parse length using shared function with proper bounds checking
	length, pos, err := parseASN1Length(data, 1)
	if err != nil {
		return nil
	}

	// Return the content bytes (already validated by parseASN1Length)
	return data[pos : pos+length]
}

// unwrapContext0 extracts content from a CONTEXT SPECIFIC [0] tagged field
// by skipping the tag and length bytes to get the raw content
func unwrapContext0(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Verify IMPLICIT [0] tag (0xA0)
	if data[0] != 0xA0 {
		return nil
	}

	// Parse length using shared function with proper bounds checking
	length, pos, err := parseASN1Length(data, 1)
	if err != nil {
		return nil
	}

	// Return the content bytes (already validated by parseASN1Length)
	return data[pos : pos+length]
}

// wrapAsSet wraps content with a SET OF tag (0x31) and proper length encoding
func wrapAsSet(content []byte) []byte {
	result := []byte{0x31} // SET tag

	// Add length encoding
	length := len(content)
	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else if length < 65536 {
		result = append(result, 0x82, byte(length>>8), byte(length))
	} else {
		// Very large structures
		result = append(result, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}

	// Add content
	return append(result, content...)
}

// parseSignedAttributes parses IMPLICIT [0] SignedAttrs back into attribute structures
//
// IMPORTANT: The IMPLICIT [0] tag replaces the SET OF tag, so the content we extract
// is the concatenated attributes without the outer SET wrapper. We must parse them
// individually, not as a SET OF structure.
//
// The structure in the CMS is:
//
//	SignedAttrs [0] IMPLICIT SET OF Attribute
//
// Which becomes:
//
//	A0 <len> <attr1> <attr2> ...  (the SET tag 31 is replaced by A0)
//
// After unwrapping the IMPLICIT [0], we have just the concatenated attributes.
func parseSignedAttributes(signedAttrs []byte) ([]attribute, error) {
	// Extract content from IMPLICIT [0]
	content := unwrapContext0(signedAttrs)
	if content == nil {
		return nil, fmt.Errorf("failed to extract content from IMPLICIT [0]")
	}

	// Parse individual attributes from the concatenated content
	// Note: The content is NOT a SET anymore, it's just concatenated attributes
	var attrs []attribute
	remaining := content
	for len(remaining) > 0 {
		var attr attribute
		rest, err := asn1.Unmarshal(remaining, &attr)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute: %w", err)
		}
		attrs = append(attrs, attr)
		remaining = rest
	}

	if len(attrs) == 0 {
		return nil, fmt.Errorf("no attributes found in SignedAttrs")
	}

	return attrs, nil
}

// constantTimeCompareBigInt performs constant-time comparison of two big integers
// Returns true if they are equal, false otherwise
func constantTimeCompareBigInt(a, b *big.Int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Get byte representations
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// For constant-time comparison, we need equal-length byte slices
	// Pad the shorter one with leading zeros
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	// Create padded versions
	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)
	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)

	return subtle.ConstantTimeCompare(aPadded, bPadded) == 1
}

// matchesSID verifies that SignerIdentifier matches certificate
// Supports both issuerAndSerialNumber and subjectKeyIdentifier
// Uses constant-time comparison for cryptographic values to prevent timing attacks
func matchesSID(sidRaw asn1.RawValue, cert *x509.Certificate) bool {
	// Check if this is a subjectKeyIdentifier (IMPLICIT [0] OCTET STRING)
	if sidRaw.Tag == 0 && sidRaw.Class == 2 {
		// This is a subjectKeyIdentifier
		var keyID []byte
		rest, err := asn1.Unmarshal(sidRaw.Bytes, &keyID)
		if err != nil || len(rest) > 0 {
			return false
		}
		// Use constant-time comparison for key IDs
		if len(cert.SubjectKeyId) == 0 || len(keyID) != len(cert.SubjectKeyId) {
			return false
		}
		return subtle.ConstantTimeCompare(keyID, cert.SubjectKeyId) == 1
	}

	// Otherwise, try to parse as issuerAndSerialNumber
	var sid issuerAndSerialNumber
	rest, err := asn1.Unmarshal(sidRaw.FullBytes, &sid)
	if err != nil || len(rest) > 0 {
		return false
	}

	// Use constant-time comparison for serial numbers
	if !constantTimeCompareBigInt(sid.SerialNumber, cert.SerialNumber) {
		return false
	}

	// Compare issuers (these are public values, but we maintain consistency)
	certIssuer := cert.Issuer.ToRDNSequence()
	if len(sid.Issuer) != len(certIssuer) {
		return false
	}

	// Compare each RDN
	for i := range sid.Issuer {
		if len(sid.Issuer[i]) != len(certIssuer[i]) {
			return false
		}
		for j := range sid.Issuer[i] {
			if !sid.Issuer[i][j].Type.Equal(certIssuer[i][j].Type) {
				return false
			}
			// Compare values as strings
			sidValue := fmt.Sprintf("%v", sid.Issuer[i][j].Value)
			certValue := fmt.Sprintf("%v", certIssuer[i][j].Value)
			if sidValue != certValue {
				return false
			}
		}
	}

	return true
}

// extractDigestFromAttribute extracts the digest value from an attribute's SET wrapper
func extractDigestFromAttribute(value asn1.RawValue) ([]byte, error) {
	// The value should be a SET containing an OCTET STRING
	if value.Tag != 17 || !value.IsCompound {
		return nil, fmt.Errorf("expected SET, got tag %d", value.Tag)
	}

	// Parse the OCTET STRING from the SET
	var digest []byte
	rest, err := asn1.Unmarshal(value.Bytes, &digest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal digest: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in digest attribute")
	}

	return digest, nil
}
