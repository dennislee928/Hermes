package hibp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hermes/internal/provider"
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

// Code implements provider.Adapter.
func (c *Client) Code() string { return "hibp" }

// SupportedTypes implements provider.Adapter.
func (c *Client) SupportedTypes() []provider.IndicatorType {
	return []provider.IndicatorType{provider.IndicatorEmail}
}

// Lookup implements provider.Adapter. Only email is supported (breached account).
func (c *Client) Lookup(ctx context.Context, indicatorType provider.IndicatorType, value string) (provider.Result, error) {
	if c.apiKey == "" {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	if indicatorType != provider.IndicatorEmail {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + string(indicatorType)}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/breachedaccount/"+value+"?truncateResponse=false", nil)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("hibp-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
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
		return provider.Result{ProviderCode: c.Code(), Success: false, Data: data, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	return provider.Result{ProviderCode: c.Code(), Success: success, Data: data}, nil
}
