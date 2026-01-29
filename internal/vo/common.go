package vo

// ErrorVO is the standard error response for 4xx/5xx.
// @description Standard error response
type ErrorVO struct {
	Code    string `json:"code" example:"BAD_REQUEST"`
	Message string `json:"message" example:"invalid request"`
}
