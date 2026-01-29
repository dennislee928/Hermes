package hibp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hermes/internal/providerapi"
)

const baseURL = "https://haveibeenpwned.com/api/v3"

// Client calls HaveIBeenPwned API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates an HIBP client. apiKey is required for breach and paste endpoints.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "hibp" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"email"}
}

// Lookup implements providerapi.Adapter. Only email is supported (breached account).
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	if indicatorType != "email" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/breachedaccount/"+value+"?truncateResponse=false", nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("hibp-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out []interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	data := map[string]interface{}{"breaches": out}
	success := resp.StatusCode == http.StatusOK
	if resp.StatusCode == http.StatusNotFound {
		success = true
		data["breaches"] = []interface{}{}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Data: data, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	return providerapi.Result{ProviderCode: c.Code(), Success: success, Data: data}, nil
}
