package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

type Policy struct {
	ID        uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name      string         `gorm:"not null" json:"name"`
	Effect    string         `gorm:"not null" json:"effect"`
	Provider  string         `gorm:"not null;default:'global'" json:"provider"`
	Resource  string         `gorm:"not null" json:"resource"`
	Actions   pq.StringArray `gorm:"type:text[]" json:"actions"`
	Condition datatypes.JSON `gorm:"type:jsonb" json:"condition"`
	Expr      string         `gorm:"type:text" json:"expr"`
	Metadata  datatypes.JSON `gorm:"type:jsonb" json:"metadata"`
	Enabled   bool           `gorm:"default:true" json:"enabled"`
	Priority  int            `gorm:"default:100" json:"priority"`
	Version   int            `gorm:"default:1" json:"version"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PolicyAudit struct {
	ID        uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Request   datatypes.JSON `gorm:"type:jsonb"`
	Decision  string
	MatchedID *uuid.UUID
	Trace     datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt time.Time
}
