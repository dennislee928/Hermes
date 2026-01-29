package ssllabs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://api.ssllabs.com/api/v3"

// Client calls SSL Labs (Qualys) API. Public API v3 does not require an API key.
type Client struct {
	client *http.Client
}

// NewClient creates an SSL Labs client.
func NewClient() *Client {
	return &Client{client: &http.Client{}}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "ssllabs" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"domain"}
}

// Lookup implements providerapi.Adapter. value is the hostname to assess (e.g. example.com).
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if indicatorType != "domain" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	u, _ := url.Parse(baseURL + "/analyze")
	q := u.Query()
	q.Set("host", value)
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
