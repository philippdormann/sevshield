package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port string
	// DatabasePath is the SQLite file. Used only when DatabaseURL is empty.
	DatabasePath string
	// DatabaseURL is a Postgres DSN (e.g.
	// postgres://user:pass@host:5432/db?sslmode=disable). When non-empty it
	// takes precedence and DatabasePath is ignored. See Dialect.
	DatabaseURL      string
	AdminToken       string
	DisableUI        bool
	KeyEncryptionHex string
	// IPSourceHeader, when set (e.g. X-Forwarded-For behind Caddy/Traefik),
	// is the source of the client IP for allowlisting. Otherwise the
	// connection remote address is used.
	IPSourceHeader string
	// CookieSecure sets the Secure flag on the session cookie. Enable in
	// production behind TLS; keep off for plain http (e.g. localhost).
	CookieSecure bool
	// ProxyTimeout is the upstream request timeout (PROXY_TIMEOUT_SECONDS,
	// default 30). Applies to proxied /api/v1/* calls only.
	ProxyTimeout time.Duration
	// ProxyMaxBodyMB caps the buffered upstream response body
	// (PROXY_MAX_BODY_MB, default 20). Larger responses are truncated.
	ProxyMaxBodyMB int
}

func Load() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data/sevshield.db"
	}
	return Config{
		Port:             port,
		DatabasePath:     dbPath,
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		AdminToken:       os.Getenv("ADMIN_TOKEN"),
		DisableUI:        isTruthy(os.Getenv("DISABLE_UI")),
		KeyEncryptionHex: os.Getenv("KEY_ENCRYPTION_KEY"),
		IPSourceHeader:   os.Getenv("IP_SOURCE_HEADER"),
		CookieSecure:     isTruthy(os.Getenv("COOKIE_SECURE")),
		ProxyTimeout:     time.Duration(parsePositiveInt(os.Getenv("PROXY_TIMEOUT_SECONDS"), 30)) * time.Second,
		ProxyMaxBodyMB:   parsePositiveInt(os.Getenv("PROXY_MAX_BODY_MB"), 20),
	}
}

func MustPort(s string) int {
	p, err := strconv.Atoi(s)
	if err != nil || p <= 0 {
		return 8080
	}
	return p
}

// Dialect reports which database backend to use. A non-empty DATABASE_URL
// selects Postgres; otherwise the server uses SQLite at DatabasePath.
// DATABASE_URL takes precedence when both are set.
func (c Config) Dialect() string {
	if c.DatabaseURL != "" {
		return "postgres"
	}
	return "sqlite"
}

func isTruthy(s string) bool {
	switch s {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	}
	return false
}

// parsePositiveInt reads a positive integer env value, falling back to def
// on empty, unparsable or non-positive input.
func parsePositiveInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
