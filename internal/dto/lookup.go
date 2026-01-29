package dto

// LookupRequestDTO is the request body for unified lookup.
// @description Request body for unified lookup
type LookupRequestDTO struct {
	// IndicatorType is one of: ip, domain, url, hash, email
	IndicatorType string `json:"indicator_type" binding:"required,oneof=ip domain url hash email" example:"ip"`
	// IndicatorValue is the value to look up (e.g. IP, domain, URL, hash, email)
	IndicatorValue string `json:"indicator_value" binding:"required" example:"8.8.8.8"`
	// Providers optionally limits which providers to query (empty = all enabled)
	Providers []string `json:"providers,omitempty"`
}
