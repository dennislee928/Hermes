package vo

// ProviderLookupResponseVO is the response for a single-provider lookup (e.g. GET /providers/abuseipdb/ip/:ip).
type ProviderLookupResponseVO struct {
	ProviderCode string      `json:"provider_code"`
	Success      bool        `json:"success"`
	Data         interface{} `json:"data,omitempty"`
	Error        string      `json:"error,omitempty"`
}
