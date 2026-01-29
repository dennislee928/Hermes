package circl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/provider"
)

const baseURL = "https://cve.circl.lu/api/cve"

// Client calls CIRCL CVE Search API (no key required).
type Client struct {
	client *http.Client
}

// NewClient creates a CIRCL CVE client.
func NewClient() *Client {
	return &Client{client: &http.Client{}}
}

// Code implements provider.Adapter.
func (c *Client) Code() string { return "circl_cve" }

// SupportedTypes implements provider.Adapter.
func (c *Client) SupportedTypes() []provider.IndicatorType {
	return []provider.IndicatorType{provider.IndicatorHash} // CVE-ID
}

// Lookup implements provider.Adapter. value should be a CVE-ID (e.g. CVE-2024-1234).
func (c *Client) Lookup(ctx context.Context, indicatorType provider.IndicatorType, value string) (provider.Result, error) {
	cveID := value
	if cveID == "" {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "empty CVE id"}, nil
	}
	u := baseURL + "/" + url.PathEscape(cveID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	success := resp.StatusCode == http.StatusOK
	if resp.StatusCode != http.StatusOK {
		return provider.Result{ProviderCode: c.Code(), Success: false, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	return provider.Result{ProviderCode: c.Code(), Success: success, Data: out}, nil
}
