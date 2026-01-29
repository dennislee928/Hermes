package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// JSONB is a type for PostgreSQL jsonb that scans/saves as []byte or map.
type JSONB map[string]interface{}

func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for JSONB")
	}
	return json.Unmarshal(b, j)
}

// LookupResult is cache/history per provider.
type LookupResult struct {
	ID               int64     `gorm:"primaryKey;autoIncrement"`
	LookupRequestID  int64     `gorm:"not null;uniqueIndex:idx_lookup_request_provider"`
	ProviderCode     string    `gorm:"type:varchar(64);not null;uniqueIndex:idx_lookup_request_provider"`
	RawResponse      JSONB     `gorm:"type:jsonb"`
	CachedAt         time.Time `gorm:"not null;autoCreateTime"`
	TTLSeconds       int       `gorm:"not null;default:3600"`
}

func (LookupResult) TableName() string { return "lookup_results" }
