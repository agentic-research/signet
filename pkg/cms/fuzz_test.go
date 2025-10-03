//go:build go1.18
// +build go1.18

package cms

import (
	"math/big"
	"testing"
)

// FuzzVerify tests the Verify function with random inputs to detect panics
// and other issues in ASN.1 parsing and certificate validation
func FuzzVerify(f *testing.F) {
	// Add seed corpus with valid and malformed CMS structures
	f.Add([]byte{0x30, 0x00})                                                       // Empty SEQUENCE
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})                                           // SEQUENCE with long form length
	f.Add([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}) // signedData OID
	f.Add([]byte{0xa0, 0x82, 0x01, 0x00})                                           // IMPLICIT [0] with long form length
	f.Add([]byte{0x31, 0x00})                                                       // Empty SET
	f.Add([]byte{0x31, 0x81, 0xff})                                                 // SET with 1-byte long form length
	f.Add([]byte{0x31, 0x82, 0xff, 0xff})                                           // SET with 2-byte long form length
	f.Add([]byte{0x31, 0x83, 0xff, 0xff, 0xff})                                     // SET with 3-byte long form length
	f.Add([]byte{0x31, 0x84, 0xff, 0xff, 0xff, 0xff})                               // SET with 4-byte long form length (unsupported)

	// Add some realistic but malformed CMS-like structures
	malformedCMS := []byte{
		0x30, 0x82, 0x01, 0x00, // ContentInfo SEQUENCE
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, // OID
		0xa0, 0x81, 0xee, // IMPLICIT [0]
		0x30, 0x81, 0xeb, // SignedData SEQUENCE
		0x02, 0x01, 0x01, // Version
		0x31, 0x00, // DigestAlgorithms SET (empty)
		0x30, 0x00, // EncapContentInfo (empty)
		0xa0, 0x00, // Certificates [0] (empty)
		0x31, 0x00, // SignerInfos SET (empty)
	}
	f.Add(malformedCMS)

	f.Fuzz(func(t *testing.T, cmsData []byte) {
		// Test with nil detached data
		_, _ = Verify(cmsData, nil, VerifyOptions{})

		// Test with empty detached data
		_, _ = Verify(cmsData, []byte{}, VerifyOptions{})

		// Test with random detached data
		_, _ = Verify(cmsData, []byte("test data"), VerifyOptions{})

		// Test with cmsData as detached data (cross-fuzzing)
		_, _ = Verify(cmsData, cmsData, VerifyOptions{})
	})
}

// FuzzParseASN1Length tests the parseASN1Length helper function
func FuzzParseASN1Length(f *testing.F) {
	// Add seed corpus with various ASN.1 length encodings
	f.Add([]byte{0x00}, 0)                               // Length 0
	f.Add([]byte{0x7f}, 0)                               // Maximum short form
	f.Add([]byte{0x81, 0x80}, 0)                         // Long form, 1 byte
	f.Add([]byte{0x82, 0x01, 0x00}, 0)                   // Long form, 2 bytes
	f.Add([]byte{0x83, 0x01, 0x00, 0x00}, 0)             // Long form, 3 bytes
	f.Add([]byte{0x84, 0x01, 0x00, 0x00, 0x00}, 0)       // Long form, 4 bytes
	f.Add([]byte{0x80}, 0)                               // Indefinite length
	f.Add([]byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, 0) // 5 bytes (too long)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, 0)             // Invalid encoding

	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		// Ensure offset is within reasonable bounds
		if offset < 0 {
			offset = 0
		}
		if offset > len(data) {
			offset = len(data)
		}

		// This should never panic
		length, newPos, err := parseASN1Length(data, offset)

		// Validate returned values are sensible
		if err == nil {
			if length < 0 {
				t.Errorf("parseASN1Length returned negative length: %d", length)
			}
			if newPos < offset {
				t.Errorf("parseASN1Length returned newPos (%d) < offset (%d)", newPos, offset)
			}
			if newPos > len(data) {
				t.Errorf("parseASN1Length returned newPos (%d) > len(data) (%d)", newPos, len(data))
			}
			if newPos+length > len(data) {
				// This should have returned an error
				t.Errorf("parseASN1Length accepted invalid length: newPos+length (%d) > len(data) (%d)",
					newPos+length, len(data))
			}
		}
	})
}

// FuzzExtractSetContent tests the extractSetContent helper function
func FuzzExtractSetContent(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0x31, 0x00})                               // Empty SET
	f.Add([]byte{0x31, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}) // SET with content
	f.Add([]byte{0x30, 0x00})                               // Wrong tag (SEQUENCE)
	f.Add([]byte{0x31, 0xff})                               // Invalid length
	f.Add([]byte{0x31})                                     // Truncated
	f.Add([]byte{})                                         // Empty input

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should never panic
		result := extractSetContent(data)

		// If we got a result, verify it's within the original data bounds
		if result != nil {
			// Check that result is a subsequence of data
			found := false
			for i := 0; i <= len(data)-len(result); i++ {
				if len(result) == 0 || string(data[i:i+len(result)]) == string(result) {
					found = true
					break
				}
			}
			if !found && len(result) > 0 {
				t.Errorf("extractSetContent returned data not present in input")
			}
		}
	})
}

// FuzzUnwrapContext0 tests the unwrapContext0 helper function
func FuzzUnwrapContext0(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0xa0, 0x00})                               // Empty IMPLICIT [0]
	f.Add([]byte{0xa0, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}) // IMPLICIT [0] with content
	f.Add([]byte{0xa1, 0x00})                               // Wrong tag (IMPLICIT [1])
	f.Add([]byte{0xa0, 0xff})                               // Invalid length
	f.Add([]byte{0xa0})                                     // Truncated
	f.Add([]byte{})                                         // Empty input

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should never panic
		result := unwrapContext0(data)

		// If we got a result, verify it's within the original data bounds
		if result != nil {
			// Check that result is a subsequence of data
			found := false
			for i := 0; i <= len(data)-len(result); i++ {
				if len(result) == 0 || string(data[i:i+len(result)]) == string(result) {
					found = true
					break
				}
			}
			if !found && len(result) > 0 {
				t.Errorf("unwrapContext0 returned data not present in input")
			}
		}
	})
}

// FuzzConstantTimeCompareBigInt tests the constant-time comparison function
func FuzzConstantTimeCompareBigInt(f *testing.F) {
	// Add seed corpus with various byte representations
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x00}, []byte{0x00})
	f.Add([]byte{0x01}, []byte{0x01})
	f.Add([]byte{0xff}, []byte{0xff})
	f.Add([]byte{0x00, 0x01}, []byte{0x01})
	f.Add([]byte{0x01, 0x00}, []byte{0x01, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff}, []byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, aBytes []byte, bBytes []byte) {
		// Limit size to prevent excessive memory usage
		if len(aBytes) > 1024 || len(bBytes) > 1024 {
			t.Skip("Skipping large inputs")
		}

		// Create big.Int values from bytes
		a := new(big.Int).SetBytes(aBytes)
		b := new(big.Int).SetBytes(bBytes)

		// Test the function (should never panic)
		result := constantTimeCompareBigInt(a, b)

		// Verify correctness
		expected := a.Cmp(b) == 0
		if result != expected {
			t.Errorf("constantTimeCompareBigInt(%v, %v) = %v, expected %v",
				a, b, result, expected)
		}

		// Test with nil values
		if constantTimeCompareBigInt(nil, nil) != true {
			t.Error("constantTimeCompareBigInt(nil, nil) should return true")
		}
		if constantTimeCompareBigInt(a, nil) != false {
			t.Error("constantTimeCompareBigInt(non-nil, nil) should return false")
		}
		if constantTimeCompareBigInt(nil, b) != false {
			t.Error("constantTimeCompareBigInt(nil, non-nil) should return false")
		}
	})
}
