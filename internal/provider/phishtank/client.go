package phishtank

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"hermes/internal/providerapi"
)

const checkURL = "https://checkurl.phishtank.com/checkurl/"

// Client calls PhishTank API.
type Client struct {
	appKey string
	client *http.Client
}

// NewClient creates a PhishTank client. appKey may be empty (optional for higher rate limit).
func NewClient(appKey string) *Client {
	return &Client{
		appKey: appKey,
		client: &http.Client{},
	}
}

// Code implements providerapi.Adapter.
func (c *Client) Code() string { return "phishtank" }

// SupportedTypes implements providerapi.Adapter.
func (c *Client) SupportedTypes() []string {
	return []string{"url"}
}

// Lookup implements providerapi.Adapter. Only URL is supported.
func (c *Client) Lookup(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
	if indicatorType != "url" {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: "unsupported type: " + indicatorType}, nil
	}

	form := url.Values{}
	form.Set("url", value)
	form.Set("format", "json")
	if c.appKey != "" {
		form.Set("app_key", c.appKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, strings.NewReader(form.Encode()))
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return providerapi.Result{ProviderCode: c.Code(), Success: false, Error: err.Error()}, err
	}
	success := resp.StatusCode == http.StatusOK
	errMsg := ""
	if !success {
		errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return providerapi.Result{ProviderCode: c.Code(), Success: success, Data: out, Error: errMsg}, nil
}
