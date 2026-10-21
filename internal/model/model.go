package model

import (
	"time"

	"gorm.io/gorm"
)

// Policy is a named allowlist. Rules are stored as JSON: [{method, path}].
type Policy struct {
	ID        string `gorm:"primaryKey;size:64"`
	Name      string `gorm:"uniqueIndex;size:128;not null"`
	RulesJSON string `gorm:"type:text;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Upstream is one sevDesk account ("god key"), stored AES-256-GCM encrypted.
// Sub-keys are bound to exactly one upstream at creation time.
type Upstream struct {
	ID           string `gorm:"primaryKey;size:64"`
	Name         string `gorm:"uniqueIndex;size:128;not null"`
	BaseURL      string `gorm:"size:512;not null"`
	GodKeySealed string `gorm:"type:text;not null"`
	KeyHint      string `gorm:"size:16;not null"`
	IsActive     bool   `gorm:"not null;default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
type ApiKey struct {
	ID        string `gorm:"primaryKey;size:64"`
	Name      string `gorm:"size:256;not null"`
	KeyHash   string `gorm:"uniqueIndex;size:64;not null"`
	KeyPrefix string `gorm:"index;size:16;not null"`
	PolicyID  string `gorm:"index;size:64;not null"`
	Policy    Policy `gorm:"foreignKey:PolicyID;references:ID"`
	// Upstream the sub-key is bound to (empty on pre-upstream rows, backfilled on open).
	UpstreamID string   `gorm:"index;size:64;not null;default:''"`
	Upstream   Upstream `gorm:"foreignKey:UpstreamID;references:ID"`
	IsActive   bool     `gorm:"not null;default:true"`
	// AllowedIPs is a comma-separated list of IPs/CIDRs; empty allows any.
	AllowedIPs string `gorm:"size:1024;not null;default:''"`
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}

// NotificationChannel delivers event alerts (denied calls, upstream errors)
// via webhook or SMTP. Secrets are stored AES-256-GCM encrypted.
type NotificationChannel struct {
	ID              string `gorm:"primaryKey;size:64"`
	Name            string `gorm:"uniqueIndex;size:128;not null"`
	Type            string `gorm:"size:16;not null"`   // webhook | smtp
	EventsJSON      string `gorm:"type:text;not null"` // e.g. ["denied","upstream_error"]
	ConfigSealed    string `gorm:"type:text;not null"`
	CooldownSeconds int    `gorm:"not null;default:300"`
	IsActive        bool   `gorm:"not null;default:true"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AdminSession is a server-side login session. Only the random ID travels
// in the httpOnly cookie, so sessions survive nothing but the DB itself.
type AdminSession struct {
	ID        string `gorm:"primaryKey;size:64"`
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index;not null"`
}

// AppSetting is a single key/value row for operator-configurable settings
// (e.g. audit retention). Generic on purpose so future settings need no
// schema change.
type AppSetting struct {
	Key       string `gorm:"primaryKey;size:128"`
	Value     string `gorm:"size:1024;not null;default:''"`
	UpdatedAt time.Time
}

// AuditLog is an append-only record of every proxied call and admin action.
type AuditLog struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time `gorm:"index;not null"`
	// Source is "proxy" or "admin". Empty on pre-source rows means proxy.
	Source string `gorm:"index;size:16"`
	// Actor is "admin"/"unknown" for admin calls; empty for proxy (see KeyPrefix).
	Actor          string `gorm:"size:64"`
	ApiKeyID       string `gorm:"index;size:64"`
	UpstreamID     string `gorm:"index;size:64"`
	KeyPrefix      string `gorm:"index;size:16"`
	Method         string `gorm:"size:16;not null"`
	Path           string `gorm:"size:1024;not null"`
	Query          string `gorm:"size:2048"`
	Status         int    `gorm:"not null"`
	UpstreamStatus int    `gorm:"not null"`
	DurationMs     int64  `gorm:"not null"`
	ClientIP       string `gorm:"size:64"`
	Error          string `gorm:"size:1024"`
}
