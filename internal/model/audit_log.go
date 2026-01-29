package model

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog records actions; no PII/full IP; anonymized fields only.
type AuditLog struct {
	ID           int64      `gorm:"primaryKey;autoIncrement"`
	RequestID    *uuid.UUID `gorm:"type:uuid"`
	Action       string     `gorm:"type:varchar(64);not null"`
	ResourceType string     `gorm:"type:varchar(64)"`
	ResourceID   string     `gorm:"type:varchar(128)"`
	IPHash       string     `gorm:"type:varchar(64)"`
	CreatedAt    time.Time  `gorm:"not null;autoCreateTime"`
}

func (AuditLog) TableName() string { return "audit_logs" }
