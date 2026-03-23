package cabundle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/agentic-research/signet/pkg/revocation/types"
)

const (
	// maxBundleSize is the maximum allowed size for a CA bundle response.
	// This prevents DoS attacks via excessively large responses.
	maxBundleSize = 10 * 1024 * 1024 // 10MB
)

// HTTPSFetcher is an implementation of the revocation.Fetcher interface that fetches
// a CA bundle from an HTTPS endpoint.
type HTTPSFetcher struct {
	client *http.Client
	url    string
}

// NewHTTPSFetcher creates a new HTTPSFetcher.
func NewHTTPSFetcher(url string, client *http.Client) *HTTPSFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPSFetcher{
		client: client,
		url:    url,
	}
}

// Fetch fetches the CA bundle for a given issuer ID.
func (f *HTTPSFetcher) Fetch(ctx context.Context, issuerID string) (*types.CABundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CA bundle: status code %d", resp.StatusCode)
	}

	// Limit response body size to prevent DoS attacks
	// io.LimitReader will return EOF after maxBundleSize bytes are read
	limitedReader := io.LimitReader(resp.Body, maxBundleSize)

	var bundle types.CABundle
	decoder := json.NewDecoder(limitedReader)
	if err := decoder.Decode(&bundle); err != nil {
		// Check if we hit the size limit
		if err == io.EOF {
			// Try to read one more byte to confirm we hit the limit
			var buf [1]byte
			if n, _ := resp.Body.Read(buf[:]); n > 0 {
				return nil, fmt.Errorf("CA bundle response too large (max %d bytes)", maxBundleSize)
			}
		}
		return nil, fmt.Errorf("failed to decode CA bundle: %w", err)
	}

	return &bundle, nil
}
