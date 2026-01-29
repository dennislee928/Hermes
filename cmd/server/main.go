package main

import (
	"log"
	"net/http"
	"strconv"

	"hermes/database"
	"hermes/internal/config"
	"hermes/internal/handler"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	var db *gorm.DB
	if cfg.PostgresDSN != "" {
		if err := database.RunMigrations(cfg.PostgresDSN); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		db, err = gorm.Open(postgres.Open(cfg.PostgresDSN), &gorm.Config{})
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
	}

	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API v1 group (lookup and provider routes)
	v1 := r.Group("/api/v1")
	handler.RegisterRoutes(v1, cfg, db)

	addr := ":" + strconv.Itoa(cfg.HTTPPort)
	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("run: %v", err)
	}
}
