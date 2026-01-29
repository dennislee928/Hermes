package vo

// LookupResponseVO is the response for unified lookup.
// @description Response for unified lookup across providers
type LookupResponseVO struct {
	RequestID      string                   `json:"request_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	IndicatorType  string                   `json:"indicator_type" example:"ip"`
	IndicatorValue string                   `json:"indicator_value,omitempty" example:""`
	Results        map[string]ProviderResultVO `json:"results"`
}

// ProviderResultVO is a single provider's result.
// @description Single provider lookup result
type ProviderResultVO struct {
	ProviderCode string      `json:"provider_code" example:"abuseipdb"`
	Success      bool        `json:"success"`
	Data         interface{} `json:"data,omitempty"`
	Error        string      `json:"error,omitempty"`
}
