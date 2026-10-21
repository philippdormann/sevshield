package db

import (
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"sevshield/internal/crypto"
	"sevshield/internal/model"
	"sevshield/internal/policy"
)

// Open connects to SQLite at path, migrates the schema and seeds policies.
// Kept for backwards compatibility; new code should call OpenSQLite or
// OpenPostgres explicitly. See Config.Dialect for backend selection.
func Open(path string, encKey []byte) (*gorm.DB, error) {
	return OpenSQLite(path, encKey)
}

// OpenSQLite connects to SQLite at path (WAL mode, 5s busy timeout),
// then migrates the schema and seeds policies. God keys are only ever added
// via the admin API. ApiKeys predating upstreams are bound to the oldest
// upstream so upgrades keep working.
func OpenSQLite(path string, encKey []byte) (*gorm.DB, error) {
	g, err := gorm.Open(sqlite.Open(path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	return migrateAndSeed(g)
}

// OpenPostgres connects to Postgres via dsn (e.g.
// "postgres://user:pass@host:5432/db?sslmode=disable"), then runs the same
// migration + seed as OpenSQLite. The schema (internal/model) is
// dialect-agnostic: plain GORM tags, no raw SQL, so AutoMigrate works on
// both backends.
func OpenPostgres(dsn string, encKey []byte) (*gorm.DB, error) {
	g, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	return migrateAndSeed(g)
}

func migrateAndSeed(g *gorm.DB) (*gorm.DB, error) {
	if err := g.AutoMigrate(&model.Policy{}, &model.Upstream{}, &model.ApiKey{}, &model.NotificationChannel{}, &model.AdminSession{}, &model.AuditLog{}, &model.AppSetting{}); err != nil {
		return nil, err
	}
	if err := seedPolicies(g); err != nil {
		return nil, err
	}
	if err := backfillKeyUpstreams(g); err != nil {
		return nil, err
	}
	return g, nil
}

func seedPolicies(g *gorm.DB) error {
	seeds := map[string][]policy.Rule{
		"sevdesk-sync": policy.DefaultSevdeskSync(),
		"readonly":     policy.DefaultReadOnly(),
	}
	for name, rules := range seeds {
		var count int64
		if err := g.Model(&model.Policy{}).Where("name = ?", name).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if err := g.Create(&model.Policy{
			ID:        "pol_" + name,
			Name:      name,
			RulesJSON: policy.MustJSON(rules),
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

func backfillKeyUpstreams(g *gorm.DB) error {
	var oldest model.Upstream
	if err := g.Order("created_at asc").First(&oldest).Error; err != nil {
		return nil // no upstreams yet; keys stay unbound until one exists
	}
	return g.Model(&model.ApiKey{}).Where("upstream_id = ?", "").Update("upstream_id", oldest.ID).Error
}

func tailHint(godKey string) string {
	godKey = strings.TrimSpace(godKey)
	if len(godKey) <= 4 {
		return "…"
	}
	return "…" + godKey[len(godKey)-4:]
}

// UpstreamBaseURL is the only sevDesk API endpoint sevshield supports.
// God keys always point here; the UI offers no base-URL input.
const UpstreamBaseURL = "https://my.sevdesk.de/api/v1"

// CreateUpstream persists a new upstream with sealed god key.
func CreateUpstream(g *gorm.DB, encKey []byte, name, godKey string) (*model.Upstream, error) {
	sealed, err := crypto.Seal(encKey, strings.TrimSpace(godKey))
	if err != nil {
		return nil, err
	}
	u := &model.Upstream{
		ID:           "ups_" + uuid.NewString(),
		Name:         strings.TrimSpace(name),
		BaseURL:      UpstreamBaseURL,
		GodKeySealed: sealed,
		KeyHint:      tailHint(godKey),
		IsActive:     true,
	}
	if err := g.Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}
