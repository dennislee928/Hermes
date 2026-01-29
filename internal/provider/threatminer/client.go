package threatminer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"hermes/internal/providerapi"
)

const baseURL = "https://api.threatminer.org/v2"

// Client calls ThreatMiner API (domain/IP/malware intelligence).
type Client struct {
	client *http.Client
}

// NewClient creates a ThreatMiner client (no API key required for public API).
func NewClient(apiKey string) *Client {
	return &Client{
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "threatminer" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"ip", "domain"}
}

// Lookup implements providerapi.Adapter.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	switch indicatorType {
	case "ip":
		return c.lookupHost(ctx, value)
	case "domain":
		return c.lookupDomain(ctx, value)
	default:
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}
}

func (c *Client) lookupHost(ctx context.Context, ip string) (providerapi.Result, error) {
	u, _ := url.Parse(baseURL + "/host.php")
	q := u.Query()
	q.Set("q", ip)
	q.Set("rt", "1") // WHOIS
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

func (c *Client) lookupDomain(ctx context.Context, domain string) (providerapi.Result, error) {
	u, _ := url.Parse(baseURL + "/domain.php")
	q := u.Query()
	q.Set("q", domain)
	q.Set("rt", "1") // WHOIS
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
