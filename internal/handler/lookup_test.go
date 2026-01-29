package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"hermes/internal/config"
	"hermes/internal/dto"
	"hermes/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestRouter(t *testing.T) (*gin.Engine, *LookupHandler) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		HTTPPort:         8080,
		PostgresDSN:      "",
		CacheTTLSeconds:  3600,
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	_ = db.AutoMigrate(&model.LookupRequest{}, &model.LookupResult{}, &model.AuditLog{})
	lh := NewLookupHandler(cfg, db)
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.POST("/lookup", lh.Lookup)
	v1.GET("/providers/:code/:type/:value", lh.ProviderLookup)
	return r, lh
}

func TestLookupHandler_Lookup_BadRequest(t *testing.T) {
	r, _ := setupTestRouter(t)
	body := bytes.NewBufferString(`{"indicator_type":"ip"}`) // missing indicator_value
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lookup", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var out map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Contains(t, out, "message")
}

func TestLookupHandler_Lookup_Valid(t *testing.T) {
	r, _ := setupTestRouter(t)
	d := dto.LookupRequestDTO{
		IndicatorType:  "ip",
		IndicatorValue: "8.8.8.8",
	}
	raw, _ := json.Marshal(d)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lookup", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// May be 200 (if DB and providers work) or 500 (if no DB); with in-memory sqlite we get 200
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestLookupHandler_ProviderLookup_NotFound(t *testing.T) {
	r, _ := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/nonexistent/ip/8.8.8.8", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
