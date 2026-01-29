package repository

import (
	"hermes/internal/model"

	"gorm.io/gorm"
)

// AuditLogRepository handles audit_logs.
type AuditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository creates a new repository.
func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// Create appends an audit log entry.
func (r *AuditLogRepository) Create(log *model.AuditLog) error {
	return r.db.Create(log).Error
}
