package service

import (
	"context"
	"testing"

	"hermes/internal/config"
	"hermes/internal/dto"
	"hermes/internal/model"
	"hermes/internal/providerapi"
	"hermes/internal/registry"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestLookupService_Lookup_IP(t *testing.T) {
	cfg := &config.Config{CacheTTLSeconds: 3600}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	_ = db.AutoMigrate(&model.LookupRequest{}, &model.LookupResult{}, &model.AuditLog{})
	reg := registry.NewRegistry(cfg)
	svc := NewLookupService(cfg, reg, db)
	d := &dto.LookupRequestDTO{
		IndicatorType:  "ip",
		IndicatorValue: "8.8.8.8",
	}
	res, err := svc.Lookup(context.Background(), d)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.RequestID)
	assert.Equal(t, "ip", res.IndicatorType)
	assert.NotNil(t, res.Results)
}

func TestLookupService_MockAdapter(t *testing.T) {
	mock := &providerapi.MockAdapter{
		CodeFunc: func() string { return "mock" },
		SupportedTypesFunc: func() []string { return []string{"ip"} },
		LookupFunc: func(ctx context.Context, indicatorType string, value string) (providerapi.Result, error) {
			return providerapi.Result{
				ProviderCode: "mock",
				Success:      true,
				Data:         map[string]interface{}{"score": 0},
			}, nil
		},
	}
	assert.Equal(t, "mock", mock.Code())
	assert.Equal(t, []string{"ip"}, mock.SupportedTypes())
	res, err := mock.Lookup(context.Background(), "ip", "8.8.8.8")
	assert.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, "mock", res.ProviderCode)
}
