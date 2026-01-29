package providerapi

import "context"

// Result holds raw response from a provider for storage and API response.
type Result struct {
	ProviderCode string
	Success      bool
	Data         map[string]interface{}
	Error        string
}

// Adapter is the common interface for all security providers.
// indicatorType is one of: ip, domain, url, hash, email.
type Adapter interface {
	Code() string
	Lookup(ctx context.Context, indicatorType string, value string) (Result, error)
	SupportedTypes() []string
}
