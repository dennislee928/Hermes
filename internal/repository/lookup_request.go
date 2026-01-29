package repository

import (
	"hermes/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// LookupRequestRepository handles lookup_requests and lookup_results.
type LookupRequestRepository struct {
	db *gorm.DB
}

// NewLookupRequestRepository creates a new repository.
func NewLookupRequestRepository(db *gorm.DB) *LookupRequestRepository {
	return &LookupRequestRepository{db: db}
}

// Create creates a lookup request and returns the request_id.
func (r *LookupRequestRepository) Create(req *model.LookupRequest) error {
	if req.RequestID == uuid.Nil {
		req.RequestID = uuid.New()
	}
	return r.db.Create(req).Error
}

// GetByRequestID loads a lookup request by request_id.
func (r *LookupRequestRepository) GetByRequestID(requestID uuid.UUID) (*model.LookupRequest, error) {
	var m model.LookupRequest
	err := r.db.Where("request_id = ?", requestID).First(&m).Error
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// CreateResult stores a lookup result for a request.
func (r *LookupRequestRepository) CreateResult(res *model.LookupResult) error {
	return r.db.Create(res).Error
}

// GetResultsByRequestID returns all results for a lookup request.
func (r *LookupRequestRepository) GetResultsByRequestID(lookupRequestID int64) ([]model.LookupResult, error) {
	var list []model.LookupResult
	err := r.db.Where("lookup_request_id = ?", lookupRequestID).Find(&list).Error
	return list, err
}
