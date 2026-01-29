package handler

import (
	"net/http"

	"hermes/internal/config"
	"hermes/internal/dto"
	"hermes/internal/registry"
	"hermes/internal/service"
	"hermes/internal/vo"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// LookupHandler handles unified lookup and per-provider lookup.
type LookupHandler struct {
	lookupSvc *service.LookupService
	registry  *registry.Registry
}

// NewLookupHandler creates a new lookup handler.
func NewLookupHandler(cfg *config.Config, db *gorm.DB) *LookupHandler {
	reg := registry.NewRegistry(cfg)
	return &LookupHandler{
		lookupSvc: service.NewLookupService(cfg, reg, db),
		registry:  reg,
	}
}

// Lookup handles POST /lookup (unified lookup).
// @Summary      Unified lookup
// @Description  Run lookup across all providers that support the indicator type
// @Tags         lookup
// @Accept       json
// @Produce      json
// @Param        body  body  dto.LookupRequestDTO  true  "Lookup request"
// @Success      200  {object}  vo.LookupResponseVO
// @Failure      400  {object}  vo.ErrorVO
// @Failure      500  {object}  vo.ErrorVO
// @Router       /lookup [post]
func (h *LookupHandler) Lookup(c *gin.Context) {
	var req dto.LookupRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, vo.ErrorVO{Code: "BAD_REQUEST", Message: err.Error()})
		return
	}
	res, err := h.lookupSvc.Lookup(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, vo.ErrorVO{Code: "INTERNAL_ERROR", Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

// ProviderLookup handles GET /providers/:code/:type/:value.
// @Summary      Single-provider lookup
// @Description  Lookup using one provider by code (e.g. abuseipdb, virustotal)
// @Tags         providers
// @Produce      json
// @Param        code   path  string  true  "Provider code (e.g. abuseipdb)"
// @Param        type   path  string  true  "Indicator type (ip, domain, url, hash, email)"
// @Param        value  path  string  true  "Indicator value"
// @Success      200  {object}  vo.ProviderLookupResponseVO
// @Failure      400  {object}  vo.ErrorVO
// @Failure      404  {object}  vo.ErrorVO
// @Failure      500  {object}  vo.ProviderLookupResponseVO
// @Router       /providers/{code}/{type}/{value} [get]
func (h *LookupHandler) ProviderLookup(c *gin.Context) {
	code := c.Param("code")
	indicatorType := c.Param("type")   // ip, domain, url, hash, email
	value := c.Param("value")
	if code == "" || indicatorType == "" || value == "" {
		c.JSON(http.StatusBadRequest, vo.ErrorVO{Code: "BAD_REQUEST", Message: "code, type, and value required"})
		return
	}
	adapter := h.registry.AdapterByCode(code)
	if adapter == nil {
		c.JSON(http.StatusNotFound, vo.ErrorVO{Code: "NOT_FOUND", Message: "provider not found"})
		return
	}
	res, err := adapter.Lookup(c.Request.Context(), indicatorType, value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, vo.ProviderLookupResponseVO{
			ProviderCode: code,
			Success:      false,
			Error:        err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, vo.ProviderLookupResponseVO{
		ProviderCode: res.ProviderCode,
		Success:      res.Success,
		Data:         res.Data,
		Error:        res.Error,
	})
}
