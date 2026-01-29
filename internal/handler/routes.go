package handler

import (
	"hermes/internal/config"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes mounts API v1 routes. cfg and db are used by lookup and provider handlers.
func RegisterRoutes(v1 *gin.RouterGroup, cfg *config.Config, db *gorm.DB) {
	v1.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	if db != nil {
		lh := NewLookupHandler(cfg, db)
		v1.POST("/lookup", lh.Lookup)
		v1.GET("/providers/:code/:type/:value", lh.ProviderLookup)
	}
}
