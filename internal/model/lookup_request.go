package model

import (
	"time"

	"github.com/google/uuid"
)

// LookupRequest is one row per lookup; indicator_value may be hashed for anonymization.
type LookupRequest struct {
	ID             int64     `gorm:"primaryKey;autoIncrement"`
	RequestID      uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"`
	IndicatorType  string    `gorm:"type:varchar(32);not null"`
	IndicatorValue string    `gorm:"type:varchar(2048);not null"`
	UserID         *string   `gorm:"type:varchar(128)"`
	CreatedAt      time.Time `gorm:"not null;autoCreateTime"`
}

func (LookupRequest) TableName() string { return "lookup_requests" }
