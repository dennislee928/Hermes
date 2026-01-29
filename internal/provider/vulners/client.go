package vulners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hermes/internal/providerapi"
)

const baseURL = "https://vulners.com/api/v3/search/lucene/"

// Client calls Vulners API (vulnerability/CVE search).
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a Vulners client. apiKey may be empty (Lookup will return not configured).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "vulners" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"hash"} // CVE-ID or search query
}

// Lookup implements providerapi.Adapter. value can be CVE-ID (e.g. CVE-2024-1234) or search query.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	if indicatorType != "hash" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}
	// Vulners: use value as CVE ID (cvelist:value) or generic search
	query := "cvelist:" + value
	payload, _ := json.Marshal(map[string]string{"query": query})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(payload))
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	if resp.StatusCode != http.StatusOK {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: fmt.Sprintf("HTTP %d", resp.StatusCode), Data: out}, nil
	}
	return providerapi.Result{ProviderCode: c.Code(), Success: true, Data: out}, nil
}
