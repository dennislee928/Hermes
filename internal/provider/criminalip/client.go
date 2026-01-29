package criminalip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://api.criminalip.io"

// Client calls CriminalIP API (IP/domain intelligence).
type Client struct {
	apiKey string
	client *http.Client
}

// NewClient creates a CriminalIP client. apiKey may be empty (Lookup will return not configured).
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "criminalip" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"ip", "domain"}
}

// Lookup implements providerapi.Adapter.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if c.apiKey == "" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "not configured"}, nil
	}
	switch indicatorType {
	case "ip":
		return c.lookupIP(ctx, value)
	case "domain":
		return c.lookupDomain(ctx, value)
	default:
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}
}

func (c *Client) lookupIP(ctx context.Context, ip string) (providerapi.Result, error) {
	u, _ := url.Parse(baseURL + "/v1/ip/summary")
	q := u.Query()
	q.Set("ip", ip)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("x-api-key", c.apiKey)
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

func (c *Client) lookupDomain(ctx context.Context, domain string) (providerapi.Result, error) {
	// CriminalIP domain: quick malicious check or lite report; use quick/malicious view for simple lookup
	u, _ := url.Parse(baseURL + "/domain/quick/malicious/view")
	q := u.Query()
	q.Set("query", domain)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("x-api-key", c.apiKey)
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
