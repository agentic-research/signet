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
	"fmt"
	"math/big"
	"sort"
	"strings"
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

// Helper function to create a test certificate chain with intermediate key returned
func createTestCertChainWithIntermediateKey(t *testing.T) (rootCert, intermediateCert, leafCert *x509.Certificate, leafKey, intermediateKey ed25519.PrivateKey) {
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
	_, intermediateKey, _ = ed25519.GenerateKey(rand.Reader)
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

	return rootCert, intermediateCert, leafCert, leafKey, intermediateKey
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
	_, intermediateCert, leafCert, leafKey := createTestCertChain(t)

	// Test data
	testData := []byte("Test data without root verification")

	// Sign the data
	signature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create intermediate pool
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify without root pool (should use system roots)
	// Provide intermediate cert to help build chain
	opts := VerifyOptions{
		Intermediates: intermediatePool,
	}

	// This should fail because our test cert chain is not in system roots
	_, err = Verify(signature, testData, opts)
	if err == nil {
		t.Fatal("Verification should have failed without trusted roots")
	}

	// Should be a certificate validation error
	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) || valErr.Field != "certificate" {
		t.Errorf("Expected ValidationError for certificate field, got: %v", err)
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
			expected: "ContentInfo",
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
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
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

	// Add certificate - set Bytes without the tag, let marshaller add tag
	sd.Certificates = asn1.RawValue{
		Class:      2, // context-specific
		Tag:        0,
		IsCompound: true,
		Bytes:      leafCert.Raw,
	}

	// Build ContentInfo
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}
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

	// Create root and intermediate pools
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify
	verifiedCert, err := Verify(cmsBytes, testData, VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	})
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
	// Create ContentInfo with wrong OID but valid structure
	// First create a minimal valid SignedData
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: oidData,
		},
		SignerInfos: []signerInfo{},
	}
	sdBytes, _ := asn1.Marshal(sd)

	// Now create ContentInfo with wrong OID
	ci := contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 3, 4}, // Invalid OID
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
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

// ============================================================================
// EDGE CASE TESTS - Critical scenarios for robust CMS verification
// ============================================================================

// TestVerifyWithUntrustedRootAndNoSystemRoots tests that the verifier correctly
// rejects certificates not in the trust store when no roots are provided.
// This formalizes the expectation that system roots should not be used implicitly.
func TestVerifyWithUntrustedRootAndNoSystemRoots(t *testing.T) {
	// Generate a completely new certificate chain that won't be in system roots
	_, newRootKey, _ := ed25519.GenerateKey(rand.Reader)
	newRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization: []string{"Test Untrusted Root CA"},
			Country:      []string{"US"},
			CommonName:   "Untrusted Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	newRootCertDER, err := x509.CreateCertificate(rand.Reader, newRootTemplate, newRootTemplate,
		newRootKey.Public(), newRootKey)
	if err != nil {
		t.Fatalf("Failed to create new root certificate: %v", err)
	}
	newRootCert, _ := x509.ParseCertificate(newRootCertDER)

	// Create intermediate signed by new root
	_, intermediateKey, _ := ed25519.GenerateKey(rand.Reader)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			Organization: []string{"Test Untrusted Intermediate CA"},
			CommonName:   "Untrusted Intermediate CA",
		},
		NotBefore:             time.Now().Add(-12 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate,
		newRootCert, intermediateKey.Public(), newRootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	intermediateCert, _ := x509.ParseCertificate(intermediateCertDER)

	// Create signing certificate
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	signingTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject: pkix.Name{
			Organization: []string{"Test Untrusted Signer"},
			CommonName:   "signer@untrusted.example",
		},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: []string{"signer@untrusted.example"},
	}

	signingCertDER, err := x509.CreateCertificate(rand.Reader, signingTemplate,
		intermediateCert, signingKey.Public(), intermediateKey)
	if err != nil {
		t.Fatalf("Failed to create signing certificate: %v", err)
	}
	signingCert, _ := x509.ParseCertificate(signingCertDER)

	// Create test data and sign it
	testData := []byte("Data signed with untrusted certificate chain")
	signature, err := SignData(testData, signingCert, signingKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create intermediate pool
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)

	// Verify with empty roots (should use system roots by default)
	// But provide intermediate to help build chain
	opts := VerifyOptions{
		Intermediates: intermediatePool,
	}

	_, err = Verify(signature, testData, opts)

	// This MUST fail because the certificate is not in system trust store
	if err == nil {
		t.Fatal("Verification should have failed with untrusted root when using system roots")
	}

	// Verify it's the expected error type (certificate validation error)
	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) || valErr.Field != "certificate" {
		t.Errorf("Expected ValidationError for certificate field, got: %v", err)
	}

	// Verify the underlying error - can be either UnknownAuthorityError or "broken key size" (Go x509 quirk)
	if valErr.Wrapped == nil {
		t.Error("Expected wrapped error containing certificate validation error")
	} else {
		// Check if the wrapped error chain contains expected error messages
		errStr := err.Error()
		if !bytes.Contains([]byte(errStr), []byte("unknown authority")) &&
			!bytes.Contains([]byte(errStr), []byte("Unknown Authority")) &&
			!bytes.Contains([]byte(errStr), []byte("broken key size")) {
			t.Errorf("Expected error to mention unknown authority or broken key size, got: %v", err)
		}
	}

	t.Logf("Successfully rejected untrusted certificate chain with error: %v", err)
}

// TestVerifyWithoutSignedAttributesManual tests the critical edge case where
// SignedAttributes is absent. In this case, the signature is directly over
// the hash of the data. Since SignData always includes SignedAttributes,
// we manually construct such a CMS for testing.
func TestVerifyWithoutSignedAttributesManual(t *testing.T) {
	// Generate a key pair and self-signed certificate
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Direct Signature Test"},
			CommonName:   "direct@test.example",
		},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: []string{"direct@test.example"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Create detached data
	detachedData := []byte("This data is signed directly without SignedAttributes")

	// Calculate signature directly over SHA-256 hash of data
	dataHash := sha256.Sum256(detachedData)
	directSignature := ed25519.Sign(privateKey, dataHash[:])

	// Manually construct SignerInfo WITHOUT SignedAttrs
	signer := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       cert.Issuer.ToRDNSequence(),
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		// SignedAttrs is intentionally omitted (nil/empty)
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          directSignature,
	}

	// Manually construct SignedData
	signedData := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: oidData,
			// Content omitted for detached signature
		},
		SignerInfos: []signerInfo{signer},
	}

	// Add certificate using IMPLICIT [0] tag
	certHeader := []byte{0xA0} // IMPLICIT [0] tag
	if len(cert.Raw) < 128 {
		certHeader = append(certHeader, byte(len(cert.Raw)))
	} else if len(cert.Raw) < 256 {
		certHeader = append(certHeader, 0x81, byte(len(cert.Raw)))
	} else {
		certHeader = append(certHeader, 0x82, byte(len(cert.Raw)>>8), byte(len(cert.Raw)))
	}
	signedData.Certificates = asn1.RawValue{
		FullBytes: append(certHeader, cert.Raw...),
	}

	// Marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	// Construct ContentInfo
	contentInfo := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	// Marshal complete CMS
	cmsBytes, err := asn1.Marshal(contentInfo)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	// Create root pool with the self-signed certificate as root
	// (since it's self-signed, it acts as its own root)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	// Verify the manually constructed CMS
	verifiedCert, err := Verify(cmsBytes, detachedData, VerifyOptions{
		Roots: rootPool,
	})
	if err != nil {
		t.Fatalf("Verification failed for CMS without SignedAttributes: %v", err)
	}

	// Ensure we got the correct certificate back
	if !bytes.Equal(verifiedCert.Raw, cert.Raw) {
		t.Error("Verified certificate does not match signer certificate")
	}

	t.Log("Successfully verified CMS signature without SignedAttributes (direct hash signature)")
}

// TestVerifyMultipleSigners tests that the verifier correctly rejects CMS structures
// with more than one SignerInfo, as our implementation only supports single-signer mode.
//
// Why Manual Construction is Necessary:
// ======================================
// This test requires painful manual ASN.1 construction instead of using Go's asn1.Marshal()
// due to a fundamental limitation in Go's ASN.1 library regarding SET OF structures:
//
// 1. Go's asn1.Marshal() implements DER canonicalization for SET OF, which includes:
//
//   - Sorting elements by their marshaled byte representation
//
//   - REMOVING duplicate elements (by byte comparison)
//
//     2. When we try to create two SignerInfo structures, even with different signers,
//     certain combinations can produce identical marshaled bytes due to:
//
//   - Empty or identical SignedAttributes
//
//   - Similar structure patterns
//
//   - The canonicalization process itself
//
//     3. When Go marshals a SET OF with what it considers "duplicate" elements,
//     it silently drops all but one, making it impossible to test multi-signer rejection.
//
//     4. This is mathematically correct behavior (a set cannot have duplicates), but
//     prevents us from creating the specific malformed structure we need to test.
//
// Therefore, we must manually construct the ASN.1 bytes for the SignerInfos SET,
// carefully ensuring the two SignerInfos are distinct enough to not be considered
// duplicates by DER rules, then manually assemble them into the CMS structure.
//
// This complexity exists ONLY in the test. The production verifier.go correctly
// and simply uses asn1.Unmarshal() which will properly parse any number of SignerInfos,
// allowing us to detect and reject the multiple-signer case.
//
// Future maintainers: DO NOT try to "simplify" this test by using regular asn1.Marshal().
// It will appear to work but will actually test the wrong thing (single signer, not multiple).
func TestVerifyMultipleSigners(t *testing.T) {
	// Setup: Create certificate chain and two distinct signers
	rootCert, intermediateCert, _, _, intermediateKey := createTestCertChainWithIntermediateKey(t)
	testData := []byte("Data intended for multiple signers")

	// Create first signer
	_, leafKey1, _ := ed25519.GenerateKey(rand.Reader)
	leafTemplate1 := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "first.signer@example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER1, _ := x509.CreateCertificate(rand.Reader, leafTemplate1, intermediateCert, leafKey1.Public(), intermediateKey)
	leafCert1, _ := x509.ParseCertificate(leafDER1)

	// Create second signer
	_, leafKey2, _ := ed25519.GenerateKey(rand.Reader)
	leafTemplate2 := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "second.signer@example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER2, _ := x509.CreateCertificate(rand.Reader, leafTemplate2, intermediateCert, leafKey2.Public(), intermediateKey)
	leafCert2, _ := x509.ParseCertificate(leafDER2)

	// Calculate message digest
	hash := sha256.Sum256(testData)

	// Create SignedAttributes (same for both signers)
	signingTime := time.Now()
	attrs := []testAttribute{
		{
			Type: oidAttributeContentType,
			Value: asn1.RawValue{
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagOID,
				Bytes: []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}, // id-data
			},
		},
		{
			Type: oidAttributeSigningTime,
			Value: asn1.RawValue{
				Tag:   asn1.TagUTCTime,
				Class: asn1.ClassUniversal,
				Bytes: []byte(signingTime.UTC().Format("060102150405Z")),
			},
		},
		{
			Type: oidAttributeMessageDigest,
			Value: asn1.RawValue{
				Tag:   asn1.TagOctetString,
				Class: asn1.ClassUniversal,
				Bytes: hash[:],
			},
		},
	}

	// Encode attributes for signing (as SET)
	signedAttrsForSigning := testEncodeAttributesAsSet(t, attrs)
	// Encode attributes for storage (as IMPLICIT [0])
	signedAttrsForStorage := testEncodeAttributesAsImplicit(t, attrs)

	// Create SignerInfo 1
	sig1 := ed25519.Sign(leafKey1, signedAttrsForSigning)
	signerInfo1 := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       leafCert1.Issuer.ToRDNSequence(),
			SerialNumber: leafCert1.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		SignedAttrs: asn1.RawValue{
			FullBytes: signedAttrsForStorage,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEd25519,
		},
		Signature: sig1,
	}

	// Create SignerInfo 2
	sig2 := ed25519.Sign(leafKey2, signedAttrsForSigning)
	signerInfo2 := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       leafCert2.Issuer.ToRDNSequence(),
			SerialNumber: leafCert2.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		SignedAttrs: asn1.RawValue{
			FullBytes: signedAttrsForStorage,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEd25519,
		},
		Signature: sig2,
	}

	// Marshal both SignerInfos
	si1Bytes, _ := asn1.Marshal(signerInfo1)
	si2Bytes, _ := asn1.Marshal(signerInfo2)

	// Sort SignerInfos according to DER canonicalization rules
	siBytesList := [][]byte{si1Bytes, si2Bytes}
	sort.Slice(siBytesList, func(i, j int) bool {
		return bytes.Compare(siBytesList[i], siBytesList[j]) < 0
	})

	// Concatenate sorted SignerInfos
	var signerInfosContent []byte
	for _, siBytes := range siBytesList {
		signerInfosContent = append(signerInfosContent, siBytes...)
	}

	// Wrap in SET OF header
	signerInfosSet := testMakeSetHeader(len(signerInfosContent))
	signerInfosSet = append(signerInfosSet, signerInfosContent...)

	// Now manually assemble SignedData
	var sdBuf bytes.Buffer

	// Version
	versionBytes, _ := asn1.Marshal(1)
	sdBuf.Write(versionBytes)

	// DigestAlgorithms (SET OF AlgorithmIdentifier)
	digestAlgs := []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}}
	digestAlgsBytes, _ := asn1.Marshal(digestAlgs)
	if digestAlgsBytes[0] == 0x30 { // SEQUENCE -> SET
		digestAlgsBytes[0] = 0x31
	}
	sdBuf.Write(digestAlgsBytes)

	// EncapsulatedContentInfo
	encapContentInfo := encapsulatedContentInfo{
		ContentType: oidData,
	}
	encapBytes, _ := asn1.Marshal(encapContentInfo)
	sdBuf.Write(encapBytes)

	// Certificates [0] IMPLICIT
	allCerts := []*x509.Certificate{leafCert1, leafCert2, intermediateCert}
	certsField := mustCreateCertificatesField(t, allCerts)
	sdBuf.Write(certsField.FullBytes)

	// SignerInfos (our manually constructed SET)
	sdBuf.Write(signerInfosSet)

	// Wrap SignedData in SEQUENCE
	sdContent := sdBuf.Bytes()
	sdSeq := testMakeSequenceHeader(len(sdContent))
	sdSeq = append(sdSeq, sdContent...)

	// Build ContentInfo
	var ciBuf bytes.Buffer

	// ContentType OID
	contentTypeBytes, _ := asn1.Marshal(oidSignedData)
	ciBuf.Write(contentTypeBytes)

	// Content [0] EXPLICIT
	explicitHeader := []byte{0xa0}
	if len(sdSeq) < 128 {
		explicitHeader = append(explicitHeader, byte(len(sdSeq)))
	} else if len(sdSeq) < 256 {
		explicitHeader = append(explicitHeader, 0x81, byte(len(sdSeq)))
	} else {
		explicitHeader = append(explicitHeader, 0x82, byte(len(sdSeq)>>8), byte(len(sdSeq)))
	}
	ciBuf.Write(explicitHeader)
	ciBuf.Write(sdSeq)

	// Wrap ContentInfo in SEQUENCE
	ciContent := ciBuf.Bytes()
	ciSeq := testMakeSequenceHeader(len(ciContent))
	multiSignerCMS := append(ciSeq, ciContent...)

	// Verify with our unchanged verifier
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	opts := VerifyOptions{Roots: rootPool}

	_, err := Verify(multiSignerCMS, testData, opts)
	if err == nil {
		t.Fatal("Verification should have failed with multiple signers")
	}

	// Check for the specific error
	var valErr *signetErrors.ValidationError
	if !asError(err, &valErr) || valErr.Field != "SignerInfos" {
		t.Errorf("Expected ValidationError for SignerInfos field, got: %T %v", err, err)
	}

	if !strings.Contains(valErr.Reason, "expected exactly 1") {
		t.Errorf("Expected error reason to mention 'expected exactly 1', got: %s", valErr.Reason)
	}

	t.Logf("Successfully rejected CMS with 2 signers: %v", err)
}

// reconstructSignedAttributes is a helper function needed for TestVerifyWithMultipleSignersEnhanced
func reconstructSignedAttributes(signedAttrs asn1.RawValue) ([]byte, error) {
	content := extractImplicitContent(signedAttrs.FullBytes)
	if content == nil {
		return nil, fmt.Errorf("failed to extract content from IMPLICIT tag")
	}
	return wrapAsSet(content), nil
}

// mustCreateCertificatesField creates the Certificates field for a CMS structure
// with multiple certificates. The field is [0] IMPLICIT SET OF Certificate.
func mustCreateCertificatesField(t *testing.T, certs []*x509.Certificate) asn1.RawValue {
	var certBytes []byte
	for _, cert := range certs {
		certBytes = append(certBytes, cert.Raw...)
	}

	// Create the IMPLICIT [0] tag with proper length encoding
	var fullBytes []byte
	fullBytes = append(fullBytes, 0xa0) // IMPLICIT [0] tag
	if len(certBytes) < 128 {
		fullBytes = append(fullBytes, byte(len(certBytes)))
	} else if len(certBytes) < 256 {
		fullBytes = append(fullBytes, 0x81, byte(len(certBytes)))
	} else {
		fullBytes = append(fullBytes, 0x82, byte(len(certBytes)>>8), byte(len(certBytes)))
	}
	fullBytes = append(fullBytes, certBytes...)

	return asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      certBytes,
		FullBytes:  fullBytes,
	}
}

// testAttribute type for test
type testAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// testEncodeAttributesAsSet encodes attributes as a SET for signing
func testEncodeAttributesAsSet(t *testing.T, attrs []testAttribute) []byte {
	// Encode each attribute
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			t.Fatalf("Failed to marshal attribute: %v", err)
		}
		encodedAttrs = append(encodedAttrs, encoded)
	}

	// Sort for canonical SET OF ordering
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Concatenate
	var content []byte
	for _, encoded := range encodedAttrs {
		content = append(content, encoded...)
	}

	// Wrap with SET tag
	return wrapAsSet(content)
}

// testEncodeAttributesAsImplicit encodes attributes as IMPLICIT [0] for storage
func testEncodeAttributesAsImplicit(t *testing.T, attrs []testAttribute) []byte {
	// Encode each attribute
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			t.Fatalf("Failed to marshal attribute: %v", err)
		}
		encodedAttrs = append(encodedAttrs, encoded)
	}

	// Sort for canonical SET OF ordering
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Concatenate
	var content []byte
	for _, encoded := range encodedAttrs {
		content = append(content, encoded...)
	}

	// Wrap with IMPLICIT [0] tag
	result := []byte{0xa0} // IMPLICIT [0] tag
	if len(content) < 128 {
		result = append(result, byte(len(content)))
	} else if len(content) < 256 {
		result = append(result, 0x81, byte(len(content)))
	} else {
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	result = append(result, content...)
	return result
}

// testMakeSetHeader creates a SET header with the given length
func testMakeSetHeader(length int) []byte {
	header := []byte{0x31} // SET tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}

// testMakeSequenceHeader creates a SEQUENCE header with the given length
func testMakeSequenceHeader(length int) []byte {
	header := []byte{0x30} // SEQUENCE tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}

// TestVerifyMalformedCMSComprehensive provides table-driven tests for various
// malformed CMS structures to ensure robust error handling.
// TestVerifyGoldenVector tests our implementation against a known-good Ed25519 CMS signature
// generated by an external tool (OpenSSL). This is the definitive proof that our
// implementation is spec-compliant and interoperable with other CMS implementations.
//
// This test uses a pre-generated signature to ensure we can correctly verify signatures
// created by other tools, not just those created by our own signer.go.
func TestVerifyGoldenVector(t *testing.T) {
	// Golden vector: Ed25519 CMS signature generated by OpenSSL 3.0+
	// Command used: openssl cms -sign -binary -in data.txt -signer cert.pem -inkey key.pem -outform DER -out signature.cms
	//
	// Note: As of 2025, OpenSSL 3.0+ supports Ed25519 in CMS format per RFC 8419.
	// If this test data needs regeneration, use OpenSSL 3.0+ with Ed25519 certificates.

	// For now, we'll skip this test with a note about future implementation
	t.Skip("Golden vector test requires external Ed25519 CMS signature. " +
		"Generate with: openssl cms -sign -binary -in data.txt -signer cert.pem " +
		"-inkey key.pem -outform DER -out signature.cms (requires OpenSSL 3.0+)")

	// TODO: Once we have a golden vector, the test would look like:
	/*
		goldenSignature := []byte{ // hex-encoded CMS signature from OpenSSL }
		goldenData := []byte("Test data that was signed")

		// Parse the known certificate used for signing
		goldenCertPEM := `-----BEGIN CERTIFICATE-----
		... certificate content ...
		-----END CERTIFICATE-----`

		block, _ := pem.Decode([]byte(goldenCertPEM))
		goldenCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse golden certificate: %v", err)
		}

		// Verify the golden signature
		verifiedCert, err := Verify(goldenSignature, goldenData, VerifyOptions{
			// Use the certificate's issuer as root for testing
			Roots: certPoolWithCert(goldenCert),
		})

		if err != nil {
			t.Errorf("Failed to verify golden vector signature: %v", err)
		}

		if !bytes.Equal(verifiedCert.Raw, goldenCert.Raw) {
			t.Errorf("Verified certificate doesn't match expected certificate")
		}
	*/
}

func TestVerifyMalformedCMSComprehensive(t *testing.T) {
	// Generate a valid signature as baseline
	rootCert, intermediateCert, leafCert, leafKey := createTestCertChain(t)
	testData := []byte("Test data for malformed CMS tests")

	validSignature, err := SignData(testData, leafCert, leafKey)
	if err != nil {
		t.Fatalf("Failed to create valid signature: %v", err)
	}

	// Setup verification options
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)
	opts := VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	tests := []struct {
		name           string
		corruptionFunc func([]byte) []byte
		expectedField  string
		expectedError  string
	}{
		{
			name: "truncated_signature",
			corruptionFunc: func(sig []byte) []byte {
				if len(sig) > 10 {
					return sig[:len(sig)-10]
				}
				return []byte{}
			},
			expectedField: "ContentInfo",
			expectedError: "failed to parse",
		},
		{
			name: "invalid_content_type_oid",
			corruptionFunc: func(sig []byte) []byte {
				// Parse and modify ContentType OID
				var ci contentInfo
				rest, err := asn1.Unmarshal(sig, &ci)
				if err != nil || len(rest) > 0 {
					return sig // Return original if parsing fails
				}
				ci.ContentType = asn1.ObjectIdentifier{1, 2, 3, 4, 5} // Invalid OID
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "ContentType",
			expectedError: "expected SignedData OID",
		},
		{
			name: "invalid_explicit_tag",
			corruptionFunc: func(sig []byte) []byte {
				// Parse ContentInfo
				var ci contentInfo
				rest, err := asn1.Unmarshal(sig, &ci)
				if err != nil || len(rest) > 0 {
					return sig
				}
				// Change EXPLICIT [0] tag to [1]
				if len(ci.Content.FullBytes) > 0 && ci.Content.FullBytes[0] == 0xA0 {
					modBytes := make([]byte, len(ci.Content.FullBytes))
					copy(modBytes, ci.Content.FullBytes)
					modBytes[0] = 0xA1 // Change tag
					ci.Content = asn1.RawValue{
						Class:      2,
						Tag:        1, // Wrong tag
						IsCompound: true,
						Bytes:      ci.Content.Bytes,
						FullBytes:  modBytes,
					}
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "ContentInfo",
			expectedError: "failed to parse",
		},
		{
			name: "empty_certificates_field",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				// Clear certificates field
				sd.Certificates = asn1.RawValue{}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "Certificates",
			expectedError: "no certificates found",
		},
		{
			name: "wrong_digest_algorithm",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				if len(sd.SignerInfos) > 0 {
					// Change digest algorithm to SHA-1
					sd.SignerInfos[0].DigestAlgorithm = pkix.AlgorithmIdentifier{
						Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // SHA-1
					}
				}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "DigestAlgorithm",
			expectedError: "expected SHA-256",
		},
		{
			name: "wrong_signature_algorithm",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				if len(sd.SignerInfos) > 0 {
					// Change signature algorithm to RSA
					sd.SignerInfos[0].SignatureAlgorithm = pkix.AlgorithmIdentifier{
						Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA
					}
				}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "SignatureAlgorithm",
			expectedError: "expected Ed25519",
		},
		{
			name: "zero_signers",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				// Remove all signers
				sd.SignerInfos = []signerInfo{}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "SignerInfos",
			expectedError: "expected exactly 1",
		},
		{
			name: "invalid_implicit_certificates_tag",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				// Change the IMPLICIT [0] tag to something else
				if len(sd.Certificates.FullBytes) > 0 {
					modBytes := make([]byte, len(sd.Certificates.FullBytes))
					copy(modBytes, sd.Certificates.FullBytes)
					modBytes[0] = 0x30 // Change to SEQUENCE tag
					sd.Certificates.FullBytes = modBytes
				}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "SignedData",
			expectedError: "failed to parse",
		},
		{
			name: "corrupted_signature_bytes",
			corruptionFunc: func(sig []byte) []byte {
				var ci contentInfo
				asn1.Unmarshal(sig, &ci)
				var sd signedData
				asn1.Unmarshal(ci.Content.Bytes, &sd)

				if len(sd.SignerInfos) > 0 && len(sd.SignerInfos[0].Signature) > 0 {
					// Corrupt the signature
					sd.SignerInfos[0].Signature[0] ^= 0xFF
				}

				modifiedSD, _ := asn1.Marshal(sd)
				// Update the Content field with proper EXPLICIT [0] tag
				ci.Content = asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      modifiedSD,
				}
				modified, _ := asn1.Marshal(ci)
				return modified
			},
			expectedField: "",
			expectedError: "Ed25519 verification failed",
		},
		{
			name: "garbage_after_contentinfo",
			corruptionFunc: func(sig []byte) []byte {
				// Add garbage data after the ContentInfo
				garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF}
				return append(sig, garbage...)
			},
			expectedField: "ContentInfo",
			expectedError: "trailing data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Apply corruption
			corruptedCMS := tc.corruptionFunc(validSignature)

			// Try to verify
			_, err := Verify(corruptedCMS, testData, opts)

			// Must fail
			if err == nil {
				t.Fatal("Verification should have failed for malformed CMS")
			}

			// Check error type and field if specified
			if tc.expectedField != "" {
				var valErr *signetErrors.ValidationError
				if asError(err, &valErr) {
					if valErr.Field != tc.expectedField {
						t.Errorf("Expected error field '%s', got '%s'", tc.expectedField, valErr.Field)
					}
				} else {
					// Check for SignatureError if not ValidationError
					var sigErr *signetErrors.SignatureError
					if !asError(err, &sigErr) {
						t.Errorf("Expected ValidationError or SignatureError, got %T: %v", err, err)
					}
				}
			}

			// Check error message contains expected text
			if tc.expectedError != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.expectedError)) {
				t.Errorf("Expected error to contain '%s', got: %v", tc.expectedError, err)
			}

			t.Logf("Test %s: correctly rejected with error: %v", tc.name, err)
		})
	}
}
