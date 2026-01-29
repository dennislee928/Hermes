package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

// Anonymize redacts sensitive parts of a value for logging (e.g. indicator_value).
// Returns a short prefix + "***" if len > 8, else "***".
func Anonymize(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***"
}

// Logger logs each request with method, path, status, latency. Does not log body by default.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		clientIP := c.ClientIP()
		method := c.Request.Method
		c.Next()

		statusCode := c.Writer.Status()
		latency := time.Since(start)
		log.Printf("[%s] %d %s %s %v", method, statusCode, path, clientIP, latency)
	}
}