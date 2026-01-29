package middleware

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/gin-gonic/gin"
)

// SensitiveKeys are JSON keys whose values should be anonymized in logs.
var SensitiveKeys = map[string]bool{
	"indicator_value": true,
	"url":             true,
	"email":           true,
	"ip":              true,
	"ipAddress":       true,
}

// AnonymizeBody returns a copy of the request body with sensitive fields redacted for logging.
func AnonymizeBody(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return "[read error]"
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return "[not json]"
	}
	redact(m)
	b, _ := json.Marshal(m)
	return string(b)
}

func redact(m map[string]interface{}) {
	for k, v := range m {
		if SensitiveKeys[k] {
			if s, ok := v.(string); ok {
				m[k] = Anonymize(s)
			}
		}
		if sub, ok := v.(map[string]interface{}); ok {
			redact(sub)
		}
	}
}
