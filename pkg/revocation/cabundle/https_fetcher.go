package cabundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jamestexas/signet/pkg/revocation/types"
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CA bundle: status code %d", resp.StatusCode)
	}

	var bundle types.CABundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("failed to decode CA bundle: %w", err)
	}

	return &bundle, nil
}
