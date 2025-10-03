// Package cms implements CMS/PKCS#7 signature verification with Ed25519 support.
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
	SID                issuerAndSerialNumber
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
//   - The signer's X.509 certificate if verification succeeds
//   - An error if verification fails at any step
func Verify(cmsSignature, detachedData []byte, opts VerifyOptions) (*x509.Certificate, error) {
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
	certBytes := extractImplicitContent(sd.Certificates.FullBytes)
	if certBytes == nil {
		return nil, signetErrors.NewValidationError("Certificates", "",
			"failed to extract certificate content", nil)
	}

	// The standard CMS format uses SET OF certificates, where certBytes should be: 31 <len> <cert1> [<cert2> ...]
	// For backward compatibility, we also support a single certificate without SET wrapper (older signer.go versions).
	var allCerts []*x509.Certificate
	var signerCert *x509.Certificate

	// Check if this is a SET OF certificates (standard format)
	if len(certBytes) > 0 && certBytes[0] == 0x31 {
		// Parse SET OF certificates manually
		// Skip the SET tag and length to get to the content
		setContent := extractSetContent(certBytes)
		if setContent == nil {
			return nil, signetErrors.NewValidationError("Certificates", "",
				"failed to extract SET content", nil)
		}

		// Parse certificates from the SET content
		remaining := setContent
		for len(remaining) > 0 {
			// Try to parse a certificate
			parsedCert, err := x509.ParseCertificate(remaining)
			if err == nil {
				// Successfully parsed a single certificate that fills the entire SET
				allCerts = append(allCerts, parsedCert)
				if matchesSID(si.SID, parsedCert) {
					signerCert = parsedCert
				}
				break
			}

			// If that didn't work, try parsing as ASN.1 structure to get individual certificates
			var rawCert asn1.RawValue
			rest, err := asn1.Unmarshal(remaining, &rawCert)
			if err != nil {
				break // No more certificates
			}

			// Parse the certificate
			parsedCert, err = x509.ParseCertificate(rawCert.FullBytes)
			if err != nil {
				remaining = rest
				continue // Skip malformed certificates
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
	if verifyOpts.CurrentTime.IsZero() {
		verifyOpts.CurrentTime = time.Now()
	}

	_, err = signerCert.Verify(verifyOpts)
	if err != nil {
		return nil, signetErrors.NewValidationError("certificate", "",
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

		// Constant-time comparison to prevent timing attacks
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
		content := extractImplicitContent(si.SignedAttrs.FullBytes)
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

	return signerCert, nil
}

// Helper Functions

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

	// Parse length
	pos := 1
	length := 0

	if data[pos] < 0x80 {
		// Short form: length is in single byte
		length = int(data[pos])
		pos++
	} else if data[pos] == 0x81 {
		// Long form with 1 byte
		if len(data) < pos+2 {
			return nil
		}
		length = int(data[pos+1])
		pos += 2
	} else if data[pos] == 0x82 {
		// Long form with 2 bytes
		if len(data) < pos+3 {
			return nil
		}
		length = int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
	} else if data[pos] == 0x83 {
		// Long form with 3 bytes
		if len(data) < pos+4 {
			return nil
		}
		length = int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
	} else {
		// Unsupported length encoding
		return nil
	}

	// Verify we have enough data
	if len(data) < pos+length {
		return nil
	}

	// Return the content bytes
	return data[pos : pos+length]
}

// extractImplicitContent extracts content from an IMPLICIT [0] tagged field
// by skipping the tag and length bytes to get the raw content
func extractImplicitContent(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Verify IMPLICIT [0] tag (0xA0)
	if data[0] != 0xA0 {
		return nil
	}

	// Parse length
	pos := 1
	length := 0

	if data[pos] < 0x80 {
		// Short form: length is in single byte
		length = int(data[pos])
		pos++
	} else if data[pos] == 0x81 {
		// Long form with 1 byte
		if len(data) < pos+2 {
			return nil
		}
		length = int(data[pos+1])
		pos += 2
	} else if data[pos] == 0x82 {
		// Long form with 2 bytes
		if len(data) < pos+3 {
			return nil
		}
		length = int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
	} else if data[pos] == 0x83 {
		// Long form with 3 bytes
		if len(data) < pos+4 {
			return nil
		}
		length = int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
	} else {
		// Unsupported length encoding
		return nil
	}

	// Verify we have enough data
	if len(data) < pos+length {
		return nil
	}

	// Return the content bytes
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
func parseSignedAttributes(signedAttrs []byte) ([]attribute, error) {
	// Extract content from IMPLICIT [0]
	content := extractImplicitContent(signedAttrs)
	if content == nil {
		return nil, fmt.Errorf("failed to extract content from IMPLICIT [0]")
	}

	// Parse attributes from the content
	var attrs []attribute
	for len(content) > 0 {
		var attr attribute
		rest, err := asn1.Unmarshal(content, &attr)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute: %w", err)
		}
		attrs = append(attrs, attr)
		content = rest
	}

	return attrs, nil
}

// matchesSID verifies that SignerIdentifier matches certificate's issuer and serial
func matchesSID(sid issuerAndSerialNumber, cert *x509.Certificate) bool {
	// Compare serial numbers
	if sid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}

	// Compare issuers
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
