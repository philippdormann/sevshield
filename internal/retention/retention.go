package retention

import (
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"sevshield/internal/model"
)

// SettingKey is the AppSetting row holding the audit retention in days.
// 0 (or missing) means unlimited: audit rows are kept forever.
const SettingKey = "audit_retention_days"

// MaxDays caps the setting so a typo cannot silently wipe recent history.
const MaxDays = 3650

// GetDays returns the configured retention in days (0 = unlimited).
func GetDays(db *gorm.DB) (int, error) {
	var s model.AppSetting
	if err := db.Where("key = ?", SettingKey).First(&s).Error; err != nil {
		return 0, nil // missing row = default (unlimited)
	}
	days, err := strconv.Atoi(s.Value)
	if err != nil || days < 0 {
		return 0, nil
	}
	return days, nil
}

// SetDays stores the retention (0 = unlimited). Values above MaxDays are rejected.
func SetDays(db *gorm.DB, days int) error {
	if days < 0 || days > MaxDays {
		return fmt.Errorf("retention must be 0 (unlimited) to %d days", MaxDays)
	}
	v := strconv.Itoa(days)
	var s model.AppSetting
	if err := db.Where("key = ?", SettingKey).First(&s).Error; err != nil {
		return db.Create(&model.AppSetting{Key: SettingKey, Value: v}).Error
	}
	return db.Model(&model.AppSetting{}).Where("key = ?", SettingKey).Update("value", v).Error
}

// Purge deletes audit rows older than days. days <= 0 is a no-op returning 0.
func Purge(db *gorm.DB, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	res := db.Where("created_at < ?", cutoff).Delete(&model.AuditLog{})
	return res.RowsAffected, res.Error
}
