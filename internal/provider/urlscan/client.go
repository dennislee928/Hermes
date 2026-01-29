package urlscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hermes/internal/providerapi"
)

const baseURL = "https://urlscan.io/api/v1"

// Client calls urlscan.io API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a urlscan.io client. apiKey may be empty (lower quota).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "urlscan" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"url", "domain"}
}

// Lookup implements providerapi.Adapter. For URL we submit a scan and return result; for domain we search.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if indicatorType != "url" && indicatorType != "domain" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	if indicatorType == "url" {
		return c.submitScan(ctx, value)
	}
	return c.search(ctx, "domain:"+value)
}

func (c *Client) submitScan(ctx context.Context, urlStr string) (providerapi.Result, error) {
	body := map[string]string{"url": urlStr, "visibility": "private"}
	if c.apiKey == "" {
		body["visibility"] = "public"
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/scan/", bytes.NewReader(raw))
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	success := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted
	return providerapi.Result{ProviderCode: c.Code(), Success: success, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
}

func (c *Client) search(ctx context.Context, q string) (providerapi.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/search/?q="+q, nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	success := resp.StatusCode == http.StatusOK
	return providerapi.Result{ProviderCode: c.Code(), Success: success, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
}
