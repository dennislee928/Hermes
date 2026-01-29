package malshare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://api.malshare.com/api.php"

// Client calls Malshare API (malware sample lookup).
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a Malshare client. apiKey may be empty (Lookup will return not configured).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "malshare" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"hash"}
}

// Lookup implements providerapi.Adapter.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	if indicatorType != "hash" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("api_key", c.apiKey)
	q.Set("action", "details")
	q.Set("hash", value)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
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
