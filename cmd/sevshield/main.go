package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"gorm.io/gorm"

	"sevshield/internal/admin"
	"sevshield/internal/config"
	"sevshield/internal/crypto"
	"sevshield/internal/db"
	"sevshield/internal/notify"
	"sevshield/internal/proxy"
	"sevshield/internal/retention"
	webui "sevshield/web"
)

func main() {
	cfg := config.Load()
	if cfg.AdminToken == "" {
		log.Fatal("ADMIN_TOKEN must be set")
	}
	encKey, err := crypto.ResolveKey(cfg.KeyEncryptionHex)
	if err != nil {
		log.Fatalf("key config: %v", err)
	}

	var database *gorm.DB
	switch cfg.Dialect() {
	case "postgres":
		var err error
		database, err = db.OpenPostgres(cfg.DatabaseURL, encKey)
		if err != nil {
			log.Fatalf("open postgres: %v", err)
		}
	default: // sqlite; DATABASE_PATH is ignored when DATABASE_URL is set
		if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
			log.Fatalf("mkdir data: %v", err)
		}
		var err error
		database, err = db.OpenSQLite(cfg.DatabasePath, encKey)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
	}

	app := fiber.New(fiber.Config{})
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{Format: "${method} ${path} ${status} ${latency}\n"}))

	app.Get("/healthz", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	px := proxy.NewWithLimits(database, encKey, cfg.IPSourceHeader, notify.New(database, encKey), proxy.Limits{
		Timeout:      cfg.ProxyTimeout,
		MaxBodyBytes: int64(cfg.ProxyMaxBodyMB) << 20,
	})

	// Enforce the stored audit retention on startup, then once a day.
	// The setting is UI-configured (default unlimited); the ticker re-reads
	// it so changes apply without a restart.
	if days, _ := retention.GetDays(database); days > 0 {
		if n, err := retention.Purge(database, days); err != nil {
			log.Printf("audit retention purge failed: %v", err)
		} else if n > 0 {
			log.Printf("audit retention: purged %d rows older than %d days", n, days)
		}
		go func() {
			t := time.NewTicker(24 * time.Hour)
			defer t.Stop()
			for range t.C {
				days, _ := retention.GetDays(database)
				if days <= 0 {
					continue
				}
				if n, err := retention.Purge(database, days); err != nil {
					log.Printf("audit retention purge failed: %v", err)
				} else if n > 0 {
					log.Printf("audit retention: purged %d rows older than %d days", n, days)
				}
			}
		}()
	}
	app.All("/api/v1/*", px.Handle)

	ad := admin.New(database, cfg.AdminToken, encKey, cfg.CookieSecure)
	// Public auth endpoints; everything else under /admin requires a session.
	app.Post("/admin/login", ad.Login)
	app.Post("/admin/logout", ad.Logout)
	app.Use("/admin", ad.Audit)
	g := app.Group("/admin")
	g.Use(ad.RequireAuth)
	g.Get("/me", ad.Me)
	g.Post("/keys", ad.CreateKey)
	g.Get("/keys", ad.ListKeys)
	g.Put("/keys/:id", ad.UpdateKey)
	g.Post("/keys/:id/rotate", ad.RotateKey)
	g.Post("/keys/:id/revoke", ad.RevokeKey)
	g.Delete("/keys/:id", ad.DeleteKey)
	g.Get("/upstreams", ad.ListUpstreams)
	g.Post("/upstreams", ad.CreateUpstream)
	g.Put("/upstreams/:id", ad.UpdateUpstream)
	g.Delete("/upstreams/:id", ad.DeleteUpstream)
	g.Post("/upstreams/:id/test", ad.TestUpstream)
	g.Get("/notify", ad.ListChannels)
	g.Post("/notify", ad.CreateChannel)
	g.Put("/notify/:id", ad.UpdateChannel)
	g.Delete("/notify/:id", ad.DeleteChannel)
	g.Post("/notify/:id/test", ad.TestChannel)
	g.Get("/stats", ad.Stats)
	g.Get("/policies", ad.ListPolicies)
	g.Post("/policies", ad.UpsertPolicy)
	g.Get("/audit", ad.ListAudit)
	g.Post("/audit/purge", ad.PurgeAudit)
	g.Get("/settings", ad.GetSettings)
	g.Put("/settings", ad.UpdateSettings)

	// Baked SvelteKit static UI (adapter-static -> web/build). Disabled with
	// DISABLE_UI=1. Falls back to a JSON hint when web/ was not built.
	switch {
	case cfg.DisableUI:
		app.Get("/", func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"service": "sevshield", "ui": "disabled"})
		})
	case hasEmbeddedUI():
		// Serve the baked SvelteKit output. Unknown paths fall back to
		// index.html (client-side routing), matching the old
		// filesystem-middleware NotFoundFile behavior.
		buildFS, err := fs.Sub(webui.FS, "build")
		if err != nil {
			log.Fatalf("ui fs: %v", err)
		}
		indexHTML, err := fs.ReadFile(buildFS, "index.html")
		if err != nil {
			log.Fatalf("ui index: %v", err)
		}
		app.Use("/", static.New("", static.Config{
			FS:         buildFS,
			Browse:     false,
			IndexNames: []string{"index.html"},
			NotFoundHandler: func(c fiber.Ctx) error {
				c.Set("Content-Type", "text/html; charset=utf-8")
				return c.Status(fiber.StatusOK).Send(indexHTML)
			},
		}))
	default:
		app.Get("/", func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"service": "sevshield", "ui": "run `bun install --cwd web && bun run --cwd web build`"})
		})
	}

	log.Printf("sevshield listening on :%s (ui=%v db=%s)", cfg.Port, !cfg.DisableUI, cfg.Dialect())
	if err := app.Listen(":"+cfg.Port, fiber.ListenConfig{DisableStartupMessage: true}); err != nil {
		log.Fatal(err)
	}
}

func hasEmbeddedUI() bool {
	entries, err := webui.FS.ReadDir("build")
	return err == nil && len(entries) > 0
}
