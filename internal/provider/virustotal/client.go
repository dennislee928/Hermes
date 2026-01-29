package virustotal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/provider"
)

const baseURL = "https://www.virustotal.com/api/v3"

// Client calls VirusTotal API.
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a VirusTotal client. apiKey may be empty.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements provider.Adapter.
func (c *Client) Code() string { return "virustotal" }

// SupportedTypes implements provider.Adapter.
func (c *Client) SupportedTypes() []provider.IndicatorType {
	return []provider.IndicatorType{provider.IndicatorIP, provider.IndicatorDomain, provider.IndicatorURL, provider.IndicatorHash}
}

// Lookup implements provider.Adapter.
func (c *Client) Lookup(ctx context.Context, indicatorType provider.IndicatorType, value string) (provider.Result, error) {
	if c.apiKey == "" {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}

	var path string
	switch indicatorType {
	case provider.IndicatorIP:
		path = "/ip_addresses/" + url.PathEscape(value)
	case provider.IndicatorDomain:
		path = "/domains/" + url.PathEscape(value)
	case provider.IndicatorURL:
		path = "/urls/" + base64.URLEncoding.EncodeToString([]byte(value))
	case provider.IndicatorHash:
		path = "/files/" + value
	default:
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + string(indicatorType)}, nil
	}

	u := baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	if resp.StatusCode != http.StatusOK {
		return provider.Result{ProviderCode: c.Code(), Success: false, Error: fmt.Sprintf("HTTP %d", resp.StatusCode), Data: out}, nil
	}
	return provider.Result{ProviderCode: c.Code(), Success: true, Data: out}, nil
}

