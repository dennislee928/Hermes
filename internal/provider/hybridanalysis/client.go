package hybridanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://hybrid-analysis.com/api/v2"

// Client calls Hybrid Analysis (Falcon Sandbox) API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a Hybrid Analysis client. apiKey may be empty (Lookup will return not configured).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "hybridanalysis" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"hash", "url"}
}

// Lookup implements providerapi.Adapter.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	switch indicatorType {
	case "hash":
		return c.lookupHash(ctx, value)
	case "url":
		return c.lookupHash(ctx, value) // URL: could submit; for lookup we use hash or search
	default:
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}
}

func (c *Client) lookupHash(ctx context.Context, hash string) (providerapi.Result, error) {
	// GET /search/hash?hash=... (v2.35+)
	u, _ := url.Parse(baseURL + "/search/hash")
	q := u.Query()
	q.Set("hash", hash)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("User-Agent", "Falcon")
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
