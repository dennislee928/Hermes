package provider

import (
	"context"
)

// IndicatorType is the type of indicator (ip, domain, url, hash, email).
type IndicatorType string

const (
	IndicatorIP     IndicatorType = "ip"
	IndicatorDomain IndicatorType = "domain"
	IndicatorURL    IndicatorType = "url"
	IndicatorHash   IndicatorType = "hash"
	IndicatorEmail  IndicatorType = "email"
)

// Result holds raw response from a provider for storage and API response.
type Result struct {
	ProviderCode string
	Success      bool
	Data         map[string]interface{}
	Error        string
}

// Adapter is the common interface for all security providers.
type Adapter interface {
	// Code returns the provider code (e.g. abuseipdb, virustotal).
	Code() string
	// Lookup performs a lookup; indicatorType and value must match provider capabilities.
	// If the provider is not configured (e.g. no API key), returns Result with Success false and Error set.
	Lookup(ctx context.Context, indicatorType IndicatorType, value string) (Result, error)
	// SupportedTypes returns indicator types this provider supports.
	SupportedTypes() []IndicatorType
}
