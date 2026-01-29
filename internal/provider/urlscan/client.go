package urlscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hermes/internal/provider"
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

// Code implements provider.Adapter.
func (c *Client) Code() string { return "urlscan" }

// SupportedTypes implements provider.Adapter.
func (c *Client) SupportedTypes() []provider.IndicatorType {
	return []provider.IndicatorType{provider.IndicatorURL, provider.IndicatorDomain}
}

// Lookup implements provider.Adapter. For URL we submit a scan and return result; for domain we search.
func (c *Client) Lookup(ctx context.Context, indicatorType provider.IndicatorType, value string) (provider.Result, error) {
	if indicatorType != provider.IndicatorURL && indicatorType != provider.IndicatorDomain {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + string(indicatorType)}, nil
	}

	if indicatorType == provider.IndicatorURL {
		return c.submitScan(ctx, value)
	}
	return c.search(ctx, "domain:"+value)
}

func (c *Client) submitScan(ctx context.Context, urlStr string) (provider.Result, error) {
	body := map[string]string{"url": urlStr, "visibility": "private"}
	if c.apiKey == "" {
		body["visibility"] = "public"
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/scan/", bytes.NewReader(raw))
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	success := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted
	return provider.Result{ProviderCode: c.Code(), Success: success, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
}

func (c *Client) search(ctx context.Context, q string) (provider.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/search/?q="+q, nil)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	success := resp.StatusCode == http.StatusOK
	return provider.Result{ProviderCode: c.Code(), Success: success, Data: out, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
}
