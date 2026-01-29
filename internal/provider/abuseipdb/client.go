package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://api.abuseipdb.com/api/v2/check"

// Client calls AbuseIPDB API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates an AbuseIPDB client. apiKey may be empty (Lookup will return not configured).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "abuseipdb" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"ip"}
}

// Lookup implements providerapi.Adapter. Only IP is supported.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	if indicatorType != "ip" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("ipAddress", value)
	q.Set("maxAgeInDays", "90")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out struct {
		Data interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	if resp.StatusCode != http.StatusOK {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: fmt.Sprintf("HTTP %d", resp.StatusCode), Data: map[string]interface{}{"response": out}}, nil
	}

	data, _ := out.Data.(map[string]interface{})
	if data == nil {
		data = make(map[string]interface{})
	}
	return providerapi.Result{ProviderCode: c.Code(), Success: true, Data: data}, nil
}
