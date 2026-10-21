package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"

	"sevshield/internal/crypto"
	"sevshield/internal/keys"
	"sevshield/internal/model"
	"sevshield/internal/notify"
	"sevshield/internal/policy"
)

type Handler struct {
	DB       *gorm.DB
	EncKey   []byte
	IPHeader string
	Notify   *notify.Notifier
	HTTP     *http.Client
	// MaxBodyBytes caps the buffered upstream response body.
	MaxBodyBytes int64
}

// Limits configures the proxy's upstream bounds.
type Limits struct {
	// Timeout is the upstream request timeout (default 30s).
	Timeout time.Duration
	// MaxBodyBytes caps the buffered upstream response body (default 20MiB).
	MaxBodyBytes int64
}

// DefaultLimits returns the built-in proxy bounds.
func DefaultLimits() Limits {
	return Limits{Timeout: 30 * time.Second, MaxBodyBytes: 20 << 20}
}

func New(db *gorm.DB, encKey []byte, ipHeader string, n *notify.Notifier) *Handler {
	return NewWithLimits(db, encKey, ipHeader, n, DefaultLimits())
}

func NewWithLimits(db *gorm.DB, encKey []byte, ipHeader string, n *notify.Notifier, l Limits) *Handler {
	if l.Timeout <= 0 {
		l.Timeout = DefaultLimits().Timeout
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = DefaultLimits().MaxBodyBytes
	}
	return &Handler{
		DB:           db,
		EncKey:       encKey,
		IPHeader:     ipHeader,
		Notify:       n,
		HTTP:         &http.Client{Timeout: l.Timeout},
		MaxBodyBytes: l.MaxBodyBytes,
	}
}

// clientIP resolves the caller address, honouring a trusted proxy header when set.
func (h *Handler) clientIP(c fiber.Ctx) string {
	if h.IPHeader != "" {
		if v := c.Get(h.IPHeader); v != "" {
			// e.g. X-Forwarded-For: client, proxy1, proxy2
			if i := strings.IndexByte(v, ','); i >= 0 {
				v = v[:i]
			}
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return c.IP()
}

// Handle proxies ALL /api/v1/* to the upstream bound to the sub-key.
func (h *Handler) Handle(c fiber.Ctx) error {
	start := time.Now()
	subKey := keys.Normalize(c.Get("Authorization"))
	keyHash := keys.Hash(subKey)
	keyPrefix := keys.Prefix(subKey)

	audit := model.AuditLog{
		Source:    "proxy",
		Method:    c.Method(),
		Path:      "/" + strings.TrimPrefix(c.Path(), "/"),
		Query:     string(c.Request().URI().QueryString()),
		ClientIP:  h.clientIP(c),
		KeyPrefix: keyPrefix,
	}

	fail := func(status int, event, msg string) error {
		audit.Status = status
		audit.UpstreamStatus = 0
		audit.DurationMs = time.Since(start).Milliseconds()
		audit.Error = msg
		_ = h.DB.Create(&audit).Error
		h.Notify.Fire(event, notify.Payload{
			KeyPrefix:  audit.KeyPrefix,
			ApiKeyID:   audit.ApiKeyID,
			UpstreamID: audit.UpstreamID,
			Method:     audit.Method,
			Path:       audit.Path,
			Status:     status,
			ClientIP:   audit.ClientIP,
			Error:      msg,
		})
		return c.Status(status).JSON(fiber.Map{"error": msg})
	}

	if subKey == "" {
		return fail(fiber.StatusUnauthorized, notify.EventDenied, "missing Authorization sub-key")
	}
	var k model.ApiKey
	if err := h.DB.Preload("Policy").Preload("Upstream").Where("key_hash = ?", keyHash).First(&k).Error; err != nil {
		return fail(fiber.StatusUnauthorized, notify.EventDenied, "invalid sub-key")
	}
	if !k.IsActive {
		return fail(fiber.StatusForbidden, notify.EventDenied, "sub-key revoked")
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return fail(fiber.StatusForbidden, notify.EventDenied, "sub-key expired")
	}
	nets, err := keys.ParseAllowedIPs(k.AllowedIPs)
	if err != nil || !keys.IPAllowed(nets, audit.ClientIP) {
		return fail(fiber.StatusForbidden, notify.EventDenied, "denied by ip policy")
	}
	audit.ApiKeyID = k.ID
	audit.UpstreamID = k.UpstreamID

	if k.UpstreamID == "" || k.Upstream.ID == "" {
		return fail(fiber.StatusServiceUnavailable, notify.EventUpstreamErr, "no upstream bound to sub-key")
	}
	if !k.Upstream.IsActive {
		return fail(fiber.StatusServiceUnavailable, notify.EventUpstreamErr, "upstream disabled")
	}
	godKey, err := crypto.Open(h.EncKey, k.Upstream.GodKeySealed)
	if err != nil {
		return fail(fiber.StatusInternalServerError, notify.EventUpstreamErr, "cannot decrypt upstream key")
	}

	rules, err := policy.Parse(k.Policy.RulesJSON)
	if err != nil {
		return fail(fiber.StatusInternalServerError, notify.EventUpstreamErr, "broken policy")
	}
	upstreamPath := strings.TrimPrefix(c.Path(), "/api/v1/")
	if !policy.Allowed(rules, c.Method(), upstreamPath) {
		return fail(fiber.StatusForbidden, notify.EventDenied, "denied by policy")
	}

	// Forward to the bound upstream, preserving method/query/body.
	target := strings.TrimSuffix(k.Upstream.BaseURL, "/") + "/" + strings.TrimPrefix(upstreamPath, "/")
	if qs := string(c.Request().URI().QueryString()); qs != "" {
		target += "?" + qs
	}
	req, err := http.NewRequest(c.Method(), target, bytes.NewReader(c.Body()))
	if err != nil {
		return fail(fiber.StatusBadGateway, notify.EventUpstreamErr, "build upstream request")
	}
	req.Header.Set("Authorization", godKey)
	if ct := c.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.HTTP.Do(req)
	if err != nil {
		return fail(fiber.StatusBadGateway, notify.EventUpstreamErr, "upstream unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, h.MaxBodyBytes))

	audit.Status = resp.StatusCode
	audit.UpstreamStatus = resp.StatusCode
	audit.DurationMs = time.Since(start).Milliseconds()
	now := time.Now()
	k.LastUsedAt = &now
	_ = h.DB.Save(&k).Error
	_ = h.DB.Create(&audit).Error
	if resp.StatusCode >= 500 {
		h.Notify.Fire(notify.EventUpstreamErr, notify.Payload{
			KeyPrefix:  audit.KeyPrefix,
			ApiKeyID:   audit.ApiKeyID,
			UpstreamID: audit.UpstreamID,
			Method:     audit.Method,
			Path:       audit.Path,
			Status:     resp.StatusCode,
			ClientIP:   audit.ClientIP,
			Error:      "upstream returned " + http.StatusText(resp.StatusCode),
		})
	}

	c.Status(resp.StatusCode)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		c.Set("Content-Type", ct)
	}
	return c.Send(body)
}
