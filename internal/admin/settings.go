package admin

import (
	"github.com/gofiber/fiber/v3"

	"sevshield/internal/retention"
)

type settingsView struct {
	AuditRetentionDays int `json:"auditRetentionDays"`
}

type updateSettingsInput struct {
	AuditRetentionDays *int `json:"auditRetentionDays"`
}

// GetSettings returns operator-configurable settings. 0 days = unlimited.
func (h *Handler) GetSettings(c fiber.Ctx) error {
	days, err := retention.GetDays(h.DB)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	return c.JSON(settingsView{AuditRetentionDays: days})
}

// UpdateSettings stores settings and immediately enforces the retention
// (old audit rows are deleted synchronously). Returns the stored setting
// plus the number of rows purged by this change.
func (h *Handler) UpdateSettings(c fiber.Ctx) error {
	var in updateSettingsInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if in.AuditRetentionDays == nil {
		return c.Status(400).JSON(fiber.Map{"error": "auditRetentionDays required (0 = unlimited)"})
	}
	if err := retention.SetDays(h.DB, *in.AuditRetentionDays); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	purged, err := retention.Purge(h.DB, *in.AuditRetentionDays)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
	}
	return c.JSON(fiber.Map{"auditRetentionDays": *in.AuditRetentionDays, "purged": purged})
}

type purgeAuditInput struct {
	// RetentionDays overrides the stored setting for this run only.
	RetentionDays *int `json:"retentionDays"`
}

// PurgeAudit deletes audit rows older than the stored retention (or the
// request override). With unlimited retention and no override it refuses
// rather than wiping the whole trail by accident.
func (h *Handler) PurgeAudit(c fiber.Ctx) error {
	var in purgeAuditInput
	_ = c.Bind().Body(&in) // empty body = use stored setting
	days, err := retention.GetDays(h.DB)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	if in.RetentionDays != nil {
		days = *in.RetentionDays
	}
	if days <= 0 {
		return c.Status(400).JSON(fiber.Map{"error": "retention is unlimited (pass retentionDays to purge once)"})
	}
	if days > retention.MaxDays {
		return c.Status(400).JSON(fiber.Map{"error": "retention too large"})
	}
	n, err := retention.Purge(h.DB, days)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "purge failed"})
	}
	return c.JSON(fiber.Map{"deleted": n, "retentionDays": days})
}
