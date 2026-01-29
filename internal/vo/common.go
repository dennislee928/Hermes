package vo

// ErrorVO is the standard error response for 4xx/5xx.
type ErrorVO struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
