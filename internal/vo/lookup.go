package vo

// LookupResponseVO is the response for unified lookup.
type LookupResponseVO struct {
	RequestID      string                   `json:"request_id"`
	IndicatorType  string                   `json:"indicator_type"`
	IndicatorValue string                   `json:"indicator_value,omitempty"` // optional for privacy
	Results        map[string]ProviderResultVO `json:"results"`
}

// ProviderResultVO is a single provider's result.
type ProviderResultVO struct {
	ProviderCode string      `json:"provider_code"`
	Success      bool        `json:"success"`
	Data         interface{} `json:"data,omitempty"`
	Error        string      `json:"error,omitempty"`
}
