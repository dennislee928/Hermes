package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds application configuration loaded from environment.
type Config struct {
	HTTPPort         int
	PostgresDSN      string
	LogLevel         string
	CacheTTLSeconds  int
	// Provider API keys (empty = skip provider)
	AbuseIPDBAPIKey           string
	VirusTotalAPIKey          string
	PhishTankAppKey           string
	GoogleSafeBrowsingAPIKey  string
	URLScanAPIKey             string
	HIBPAPIKey                string
	NVDAPIKey                 string
	BinaryEdgeAPIKey          string
	CriminalIPAPIKey          string
}

// Load reads .env if present and populates Config from environment.
func Load() (*Config, error) {
	_ = godotenv.Load() // ignore error if .env missing

	port, _ := strconv.Atoi(getEnv("HTTP_PORT", "8080"))
	cacheTTL, _ := strconv.Atoi(getEnv("CACHE_TTL_SECONDS", "3600"))

	return &Config{
		HTTPPort:                  port,
		PostgresDSN:               getEnv("POSTGRES_DSN", "host=localhost user=hermes password=changeme dbname=hermes sslmode=disable"),
		LogLevel:                  getEnv("LOG_LEVEL", "info"),
		CacheTTLSeconds:           cacheTTL,
		AbuseIPDBAPIKey:           getEnv("ABUSEIPDB_API_KEY", ""),
		VirusTotalAPIKey:          getEnv("VIRUSTOTAL_API_KEY", ""),
		PhishTankAppKey:           getEnv("PHISHTANK_APP_KEY", ""),
		GoogleSafeBrowsingAPIKey:  getEnv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
		URLScanAPIKey:             getEnv("URLSCAN_API_KEY", ""),
		HIBPAPIKey:                getEnv("HIBP_API_KEY", ""),
		NVDAPIKey:                 getEnv("NVD_API_KEY", ""),
		BinaryEdgeAPIKey:          getEnv("BINARYEDGE_API_KEY", ""),
		CriminalIPAPIKey:          getEnv("CRIMINALIP_API_KEY", ""),
	}, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
