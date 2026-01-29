package service

import (
	"context"
	"sync"

	"hermes/internal/config"
	"hermes/internal/dto"
	"hermes/internal/model"
	"hermes/internal/provider"
	"hermes/internal/registry"
	"hermes/internal/repository"
	"hermes/internal/vo"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// LookupService performs unified lookups and persists results.
type LookupService struct {
	cfg      *config.Config
	registry *registry.Registry
	reqRepo  *repository.LookupRequestRepository
	auditRepo *repository.AuditLogRepository
	db       *gorm.DB
}

// NewLookupService creates a new lookup service.
func NewLookupService(cfg *config.Config, reg *registry.Registry, db *gorm.DB) *LookupService {
	return &LookupService{
		cfg:       cfg,
		registry:  reg,
		reqRepo:   repository.NewLookupRequestRepository(db),
		auditRepo: repository.NewAuditLogRepository(db),
		db:        db,
	}
}

// Lookup runs a unified lookup: creates request, calls adapters in parallel, stores results, returns VO.
func (s *LookupService) Lookup(ctx context.Context, d *dto.LookupRequestDTO) (*vo.LookupResponseVO, error) {
	indicatorType := provider.IndicatorType(d.IndicatorType)
	adapters := s.registry.AdaptersForType(indicatorType)
	if len(d.Providers) > 0 {
		filtered := make([]provider.Adapter, 0)
		allowed := make(map[string]bool)
		for _, p := range d.Providers {
			allowed[p] = true
		}
		for _, a := range adapters {
			if allowed[a.Code()] {
				filtered = append(filtered, a)
			}
		}
		adapters = filtered
	}

	req := &model.LookupRequest{
		RequestID:      uuid.New(),
		IndicatorType:  d.IndicatorType,
		IndicatorValue: d.IndicatorValue,
	}
	if err := s.reqRepo.Create(req); err != nil {
		return nil, err
	}

	results := make(map[string]vo.ProviderResultVO)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range adapters {
		wg.Add(1)
		go func(adapter provider.Adapter) {
			defer wg.Done()
			res, err := adapter.Lookup(ctx, indicatorType, d.IndicatorValue)
			mu.Lock()
			results[adapter.Code()] = vo.ProviderResultVO{
				ProviderCode: res.ProviderCode,
				Success:      res.Success,
				Data:         res.Data,
				Error:        res.Error,
			}
			mu.Unlock()
			if err == nil && res.Success && res.Data != nil {
				_ = s.reqRepo.CreateResult(&model.LookupResult{
					LookupRequestID: req.ID,
					ProviderCode:    res.ProviderCode,
					RawResponse:     model.JSONB(res.Data),
					TTLSeconds:      s.cfg.CacheTTLSeconds,
				})
			}
		}(a)
	}
	wg.Wait()

	// Optional: audit log (no PII)
	_ = s.auditRepo.Create(&model.AuditLog{
		RequestID:    &req.RequestID,
		Action:       "lookup",
		ResourceType: "lookup_request",
		ResourceID:   req.RequestID.String(),
	})

	return &vo.LookupResponseVO{
		RequestID:      req.RequestID.String(),
		IndicatorType:  d.IndicatorType,
		IndicatorValue: d.IndicatorValue,
		Results:        results,
	}, nil
}
