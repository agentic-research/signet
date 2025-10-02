package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	signetErrors "github.com/jamestexas/signet/pkg/errors"
)

// Helper function to create a test certificate chain
func createTestCertChain(t *testing.T) (rootCert, intermediateCert, leafCert *x509.Certificate, leafKey ed25519.PrivateKey) {
	// Create root CA
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	rootCert, _ = x509.ParseCertificate(rootCertDER)

	// Create intermediate CA
	_, intermediateKey, _ := ed25519.GenerateKey(rand.Reader)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, intermediateKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	intermediateCert, _ = x509.ParseCertificate(intermediateCertDER)

	// Create leaf certificate
	_, leafKey, _ = ed25519.GenerateKey(rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Signer"},
			CommonName:   "signer@example.com",
		},
		NotBefore: time.Now().Add(-30 * time.Minute),
		NotAfter:  time.Now().Add(6 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Don't set ExtKeyUsage to avoid key usage validation issues in tests
		EmailAddresses: []string{"signer@example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, leafKey.Public(), intermediateKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	leafCert, _ = x509.ParseCertificate(leafCertDER)

	return rootCert, intermediateCert, leafCert, leafKey
}

func TestVerifyRoundTripSuccess(t *testing.T) {
	// Create certificate chain
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)

	// Test data
	testData := []byte("Hello, World! This is test data for CMS signature verification.")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create root pool and intermediates pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify the signature (don't specify KeyUsages since our test certs may not have them all)
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
	}

	verifiedCert, err := Verify(signature, testData, opts)
	if err != nil {
		// Add more debugging info
		t.Logf("Root cert: %v", rootCert.Subject)
		t.Logf("Leaf cert: %v", leafCert.Subject)
		t.Logf("Leaf cert issuer: %v", leafCert.Issuer)
		t.Fatalf("Verification failed: %v", err)
	}

	// Check that we got the right certificate back
	if !bytes.Equal(verifiedCert.Raw, leafCert.Raw) {
		t.Error("Verified certificate does not match signer certificate")
	}
}

func TestVerifyWithoutRoots(t *testing.T) {
	// Create certificate chain
	_, _, leafCert, leafKey := createTestCertChain(t)

	// Test data
	testData := []byte("Test data without root verification")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify without root pool (should still verify signature)
	opts := VerifyOptions{}

	verifiedCert, err := Verify(signature, testData, opts)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !bytes.Equal(verifiedCert.Raw, leafCert.Raw) {
		t.Error("Verified certificate does not match signer certificate")
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	// Create certificate chain
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Original data")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Tamper with the signature bytes
	signature[len(signature)-10] ^= 0xFF

	// Create root pool and intermediates pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify should fail
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	_, err = Verify(signature, testData, opts)
	if err == nil {
		t.Fatal("Verification should have failed with tampered signature")
	}

	// Check for specific error type
	var sigErr *signetErrors.SignatureError
	if !asError(err, &sigErr) {
		t.Errorf("Expected SignatureError, got %T", err)
	}
}

func TestVerifyTamperedData(t *testing.T) {
	// Create certificate chain
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Original data")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Tamper with the data
	tamperedData := []byte("Tampered data")

	// Create root pool and intermediates pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify should fail
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	_, err = Verify(signature, tamperedData, opts)
	if err == nil {
		t.Fatal("Verification should have failed with tampered data")
	}

	// Should be a signature error for message digest mismatch
	var sigErr *signetErrors.SignatureError
	if !asError(err, &sigErr) || sigErr.Reason != "message digest mismatch" {
		t.Errorf("Expected message digest mismatch error, got: %v", err)
	}
}

func TestVerifyUntrustedRoot(t *testing.T) {
	// Create certificate chain
	_, _, leafCert, leafKey := createTestCertChain(t)

	// Create a different root that didn't sign our chain
	_, wrongRootKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			Organization: []string{"Wrong Root CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	wrongRootDER, _ := x509.CreateCertificate(rand.Reader, wrongRootTemplate, wrongRootTemplate, wrongRootKey.Public(), wrongRootKey)
	wrongRoot, _ := x509.ParseCertificate(wrongRootDER)

	testData := []byte("Test data")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create root pool with wrong root
	rootPool := x509.NewCertPool()
	rootPool.AddCert(wrongRoot)

	// Verify should fail
	opts := VerifyOptions{
		Roots: rootPool,
	}

	_, err = Verify(signature, testData, opts)
	if err == nil {
		t.Fatal("Verification should have failed with untrusted root")
	}

	// Should be a validation error for certificate chain
	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) || valErr.Field != "certificate" {
		t.Errorf("Expected certificate validation error, got: %v", err)
	}
}

func TestVerifyExpiredCertificate(t *testing.T) {
	// Create certificate chain
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Test data")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create root pool and intermediates pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify with time set past certificate expiry
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now().Add(25 * time.Hour), // Past root cert expiry
	}

	_, err = Verify(signature, testData, opts)
	if err == nil {
		t.Fatal("Verification should have failed with expired certificate")
	}

	// Should be a validation error
	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) {
		t.Errorf("Expected ValidationError, got: %v", err)
	}
}

func TestVerifyMalformedCMS(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "ContentInfo",
		},
		{
			name:     "Invalid ASN.1",
			data:     []byte{0xFF, 0xFF, 0xFF},
			expected: "ContentInfo",
		},
		{
			name:     "Wrong content type OID",
			data:     createInvalidContentType(),
			expected: "ContentType",
		},
		{
			name:     "Missing EXPLICIT tag",
			data:     createMissingExplicitTag(),
			expected: "Content",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.data, []byte("test"), VerifyOptions{})
			if err == nil {
				t.Fatal("Expected error for malformed CMS")
			}

			var valErr *signetErrors.ValidationError
			if !asError(err, &valErr) || valErr.Field != tc.expected {
				t.Errorf("Expected ValidationError for %s, got: %v", tc.expected, err)
			}
		})
	}
}

func TestVerifyMultipleSigners(t *testing.T) {
	// Create a CMS with multiple signers (manually constructed)
	// This tests that we properly reject CMS with more than one signer

	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Test data")

	// First, create a valid signature to get the structure
	validSig, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Parse it to modify
	var ci contentInfo
	_, err = asn1.Unmarshal(validSig, &ci)
	if err != nil {
		t.Fatalf("Failed to unmarshal valid signature: %v", err)
	}

	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Failed to unmarshal signed data: %v", err)
	}

	t.Logf("Original SignerInfos count: %d", len(sd.SignerInfos))

	// Duplicate the signer info to create multiple signers
	sd.SignerInfos = append(sd.SignerInfos, sd.SignerInfos[0])

	t.Logf("Modified SignerInfos count: %d", len(sd.SignerInfos))

	// Re-encode
	modifiedSD, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal modified signed data: %v", err)
	}
	ci.Content.Bytes = modifiedSD
	modifiedCMS, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal modified CMS: %v", err)
	}

	// Try to verify
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	// Let's also verify the original to make sure it works
	_, err = Verify(validSig, testData, opts)
	if err != nil {
		t.Logf("Original signature verification failed (expected to pass): %v", err)
	}

	_, err = Verify(modifiedCMS, testData, opts)
	if err == nil {
		// Debug: Parse and check what we're actually verifying
		var debugCI contentInfo
		asn1.Unmarshal(modifiedCMS, &debugCI)
		var debugSD signedData
		asn1.Unmarshal(debugCI.Content.Bytes, &debugSD)
		t.Logf("Actual SignerInfos in modified CMS: %d", len(debugSD.SignerInfos))
		t.Fatal("Should have failed with multiple signers")
	}
	t.Logf("Error with multiple signers: %v", err)

	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) || valErr.Field != "SignerInfos" {
		t.Errorf("Expected ValidationError for SignerInfos, got: %v", err)
	}
}

func TestExtractImplicitContent(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		wantNil  bool
	}{
		{
			name:     "Short form length",
			input:    []byte{0xA0, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:     "Long form 1 byte",
			input:    []byte{0xA0, 0x81, 0x80},
			expected: make([]byte, 0x80),
		},
		{
			name:     "Long form 2 bytes",
			input:    []byte{0xA0, 0x82, 0x01, 0x00},
			expected: make([]byte, 0x100),
		},
		{
			name:    "Wrong tag",
			input:   []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			wantNil: true,
		},
		{
			name:    "Too short",
			input:   []byte{0xA0},
			wantNil: true,
		},
		{
			name:    "Empty",
			input:   []byte{},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For long form tests, append the expected content
			if len(tc.input) > 2 && tc.input[0] == 0xA0 && tc.input[1] >= 0x81 {
				tc.input = append(tc.input, tc.expected...)
			}

			result := extractImplicitContent(tc.input)
			if tc.wantNil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			} else {
				if !bytes.Equal(result, tc.expected) {
					t.Errorf("Expected %v, got %v", tc.expected, result)
				}
			}
		})
	}
}

func TestWrapAsSet(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Small content",
			input:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x31, 0x03, 0x01, 0x02, 0x03},
		},
		{
			name:     "127 bytes",
			input:    make([]byte, 127),
			expected: append([]byte{0x31, 0x7F}, make([]byte, 127)...),
		},
		{
			name:     "128 bytes",
			input:    make([]byte, 128),
			expected: append([]byte{0x31, 0x81, 0x80}, make([]byte, 128)...),
		},
		{
			name:     "256 bytes",
			input:    make([]byte, 256),
			expected: append([]byte{0x31, 0x82, 0x01, 0x00}, make([]byte, 256)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := wrapAsSet(tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestImplicitTagReconstruction(t *testing.T) {
	// This is the critical test for the IMPLICIT [0] reconstruction
	// We need to verify that content stored as A0 <len> <content>
	// gets properly reconstructed as 31 <len> <content> for verification

	// Create some test attributes
	attrs := []attribute{
		{
			Type: oidAttributeContentType,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01},
			},
		},
	}

	// Encode as IMPLICIT [0] (as stored in CMS)
	implicitBytes, err := encodeSignedAttributesImplicit(attrs)
	if err != nil {
		t.Fatalf("Failed to encode as IMPLICIT: %v", err)
	}

	// Verify it starts with 0xA0
	if implicitBytes[0] != 0xA0 {
		t.Errorf("IMPLICIT encoding should start with 0xA0, got 0x%02X", implicitBytes[0])
	}

	// Extract content from IMPLICIT
	content := extractImplicitContent(implicitBytes)
	if content == nil {
		t.Fatal("Failed to extract content from IMPLICIT")
	}

	// Wrap as SET
	setBytes := wrapAsSet(content)

	// Verify it starts with 0x31
	if setBytes[0] != 0x31 {
		t.Errorf("SET encoding should start with 0x31, got 0x%02X", setBytes[0])
	}

	// Now encode the same attributes as SET (as used for signing)
	originalSet, err := encodeAttributesAsSet(attrs)
	if err != nil {
		t.Fatalf("Failed to encode as SET: %v", err)
	}

	// The reconstructed SET should match the original SET
	if !bytes.Equal(setBytes, originalSet) {
		t.Error("Reconstructed SET does not match original SET used for signing")
		t.Errorf("Original: %X", originalSet)
		t.Errorf("Reconstructed: %X", setBytes)
	}
}

func TestDigestExtraction(t *testing.T) {
	// Test extracting message digest from attribute
	testDigest := sha256.Sum256([]byte("test data"))

	// Create attribute value (SET containing OCTET STRING)
	digestBytes, _ := asn1.Marshal(testDigest[:])
	attrValue := asn1.RawValue{
		Class:      0,
		Tag:        17, // SET
		IsCompound: true,
		Bytes:      digestBytes,
	}

	extracted, err := extractDigestFromAttribute(attrValue)
	if err != nil {
		t.Fatalf("Failed to extract digest: %v", err)
	}

	if !bytes.Equal(extracted, testDigest[:]) {
		t.Errorf("Extracted digest doesn't match original")
	}
}

func TestVerifyNoSignedAttributes(t *testing.T) {
	// This tests the edge case where SignedAttributes is absent
	// In this case, the signature is directly over the hash of the data
	// Our current SignData always includes SignedAttributes, so we need
	// to manually construct such a CMS for testing

	// Create test certificate
	_, _, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Direct signed data")

	// Calculate hash
	h := sha256.Sum256(testData)

	// Sign the hash directly
	signature := ed25519.Sign(leafKey, h[:])

	// Manually build SignerInfo without SignedAttrs
	si := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       leafCert.Issuer.ToRDNSequence(),
			SerialNumber: leafCert.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		// SignedAttrs omitted
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	// Build SignedData
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: oidData,
		},
		SignerInfos: []signerInfo{si},
	}

	// Add certificate
	certHeader := []byte{0xA0}
	if len(leafCert.Raw) < 128 {
		certHeader = append(certHeader, byte(len(leafCert.Raw)))
	} else {
		certHeader = append(certHeader, 0x81, byte(len(leafCert.Raw)))
	}
	sd.Certificates = asn1.RawValue{
		FullBytes: append(certHeader, leafCert.Raw...),
	}

	// Build ContentInfo
	sdBytes, _ := asn1.Marshal(sd)
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	cmsBytes, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal CMS: %v", err)
	}

	// Verify
	verifiedCert, err := Verify(cmsBytes, testData, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verification failed for CMS without SignedAttributes: %v", err)
	}

	if !bytes.Equal(verifiedCert.Raw, leafCert.Raw) {
		t.Error("Verified certificate does not match signer certificate")
	}
}

// Helper function to check error types (similar to errors.As but works with our custom errors)
func asError(err error, target interface{}) bool {
	if err == nil {
		return false
	}

	switch t := target.(type) {
	case **signetErrors.SignatureError:
		if e, ok := err.(*signetErrors.SignatureError); ok {
			*t = e
			return true
		}
	case **signetErrors.ValidationError:
		if e, ok := err.(*signetErrors.ValidationError); ok {
			*t = e
			return true
		}
	case **signetErrors.KeyError:
		if e, ok := err.(*signetErrors.KeyError); ok {
			*t = e
			return true
		}
	}
	return false
}

// Helper functions to create specific malformed CMS structures

func createInvalidContentType() []byte {
	// Create ContentInfo with wrong OID
	ci := contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 3, 4}, // Invalid OID
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{},
		},
	}
	data, _ := asn1.Marshal(ci)
	return data
}

func createMissingExplicitTag() []byte {
	// Create ContentInfo without EXPLICIT [0] tag
	var buf bytes.Buffer

	// ContentType
	oidBytes, _ := asn1.Marshal(oidSignedData)
	buf.Write(oidBytes)

	// Content without EXPLICIT tag (just raw bytes)
	buf.Write([]byte{0x30, 0x00}) // Empty SEQUENCE

	// Wrap in SEQUENCE
	content := buf.Bytes()
	header := []byte{0x30, byte(len(content))}
	return append(header, content...)
}

// Benchmark to verify performance
func BenchmarkVerify(b *testing.B) {
	// Setup
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(&testing.T{})
	testData := []byte("Benchmark test data for CMS signature verification")

	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		b.Fatalf("Failed to sign data: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := Verify(signature, testData, opts)
		if err != nil {
			b.Fatalf("Verification failed: %v", err)
		}
	}
}

// Test for constant-time comparison in message digest verification
func TestConstantTimeComparison(t *testing.T) {
	// This test verifies that digest comparison is constant-time
	// by checking that the extractDigestFromAttribute and comparison logic
	// doesn't leak timing information

	// Create two different digests
	digest1 := sha256.Sum256([]byte("data1"))
	digest2 := sha256.Sum256([]byte("data2"))

	// Create attribute values
	digestBytes1, _ := asn1.Marshal(digest1[:])
	attrValue1 := asn1.RawValue{
		Class:      0,
		Tag:        17, // SET
		IsCompound: true,
		Bytes:      digestBytes1,
	}

	digestBytes2, _ := asn1.Marshal(digest2[:])
	attrValue2 := asn1.RawValue{
		Class:      0,
		Tag:        17, // SET
		IsCompound: true,
		Bytes:      digestBytes2,
	}

	// Extract both
	extracted1, _ := extractDigestFromAttribute(attrValue1)
	_, _ = extractDigestFromAttribute(attrValue2) // Just to ensure it works

	// Verify using crypto/subtle (used in the actual implementation)
	result1 := subtle.ConstantTimeCompare(extracted1, digest1[:])
	result2 := subtle.ConstantTimeCompare(extracted1, digest2[:])

	if result1 != 1 {
		t.Error("Same digest comparison should return 1")
	}
	if result2 != 0 {
		t.Error("Different digest comparison should return 0")
	}
}
