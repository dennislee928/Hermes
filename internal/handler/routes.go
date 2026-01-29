package handler

import (
	"hermes/internal/config"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts API v1 routes. cfg is used by handlers and providers.
func RegisterRoutes(v1 *gin.RouterGroup, cfg *config.Config) {
	_ = cfg // used when lookup and provider handlers are added
	// Placeholder: health is on root; v1 routes added in later steps
	v1.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})
}
