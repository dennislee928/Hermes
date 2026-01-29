package model

import "time"

// Provider is the supplier master for enabled/rate-limit; API keys live in .env only.
type Provider struct {
	ID                int64     `gorm:"primaryKey;autoIncrement"`
	Code              string    `gorm:"type:varchar(64);uniqueIndex;not null"`
	Name              string    `gorm:"type:varchar(255);not null"`
	BaseURL           string    `gorm:"type:varchar(512)"`
	Enabled           bool      `gorm:"not null;default:true"`
	RateLimitPerMin   int       `gorm:"not null;default:60"`
	CreatedAt         time.Time `gorm:"not null;autoCreateTime"`
	UpdatedAt         time.Time `gorm:"not null;autoUpdateTime"`
}

func (Provider) TableName() string { return "providers" }
