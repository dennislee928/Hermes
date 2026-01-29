package ipasnhistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://bgpranking-ng.circl.lu/ipasn_history/"

// Client calls CIRCL D4 IP ASN History API (no key required).
type Client struct {
	client *http.Client
}

// NewClient creates an IP ASN History client.
func NewClient(apiKey string) *Client {
	return &Client{
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "ipasnhistory" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"ip"}
}

// Lookup implements providerapi.Adapter. Only IP is supported.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if indicatorType != "ip" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("ip", value)
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
