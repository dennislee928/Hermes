package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/provider"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Client calls NVD (National Vulnerability Database) API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates an NVD client. apiKey is optional (higher rate limit with key).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements provider.Adapter.
func (c *Client) Code() string { return "nvd" }

// SupportedTypes implements provider.Adapter.
func (c *Client) SupportedTypes() []provider.IndicatorType {
	return []provider.IndicatorType{provider.IndicatorHash} // CVE id treated as keyword; we use keywordSearch for CVE-ID
}

// Lookup implements provider.Adapter. value can be a CVE-ID (e.g. CVE-2024-1234) or keyword.
func (c *Client) Lookup(ctx context.Context, indicatorType provider.IndicatorType, value string) (provider.Result, error) {
	// NVD supports CVE lookup; we accept hash type for CVE-ID or add a generic "cve" type. Use indicator as keyword.
	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("keywordSearch", value)
	q.Set("resultsPerPage", "10")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	success := resp.StatusCode == http.StatusOK
	if resp.StatusCode != http.StatusOK {
		return provider.Result{ProviderCode: c.Code(), Success: false, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	return provider.Result{ProviderCode: c.Code(), Success: success, Data: out}, nil
}
