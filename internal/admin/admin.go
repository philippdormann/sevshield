package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"sevshield/internal/crypto"
	"sevshield/internal/db"
	"sevshield/internal/keys"
	"sevshield/internal/model"
	"sevshield/internal/notify"
	"sevshield/internal/policy"
	"sevshield/internal/session"
)

type Handler struct {
	DB           *gorm.DB
	AdminToken   string
	EncKey       []byte
	Sessions     *session.Store
	CookieSecure bool
}

func New(database *gorm.DB, adminToken string, encKey []byte, cookieSecure bool) *Handler {
	return &Handler{
		DB:           database,
		AdminToken:   adminToken,
		EncKey:       encKey,
		Sessions:     session.New(database, 24*time.Hour),
		CookieSecure: cookieSecure,
	}
}

const sessionCookie = "sevshield_session"

type loginInput struct {
	Token string `json:"token"`
}

// Login verifies the admin token and issues an httpOnly session cookie.
// The token itself is never stored in the browser.
func (h *Handler) Login(c fiber.Ctx) error {
	var in loginInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if h.AdminToken == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(in.Token)), []byte(h.AdminToken)) != 1 {
		return c.Status(401).JSON(fiber.Map{"error": "invalid token"})
	}
	id, err := h.Sessions.Create()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "session failed"})
	}
	c.Locals("actor", "admin")
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   86400,
		HTTPOnly: true,
		Secure:   h.CookieSecure,
		SameSite: "Strict",
	})
	return c.JSON(fiber.Map{"ok": true})
}

// Logout revokes the session and clears the cookie.
func (h *Handler) Logout(c fiber.Ctx) error {
	h.Sessions.Revoke(c.Cookies(sessionCookie))
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		SameSite: "Strict",
	})
	return c.JSON(fiber.Map{"ok": true})
}

// Me validates the current session (used by the UI on load).
func (h *Handler) Me(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) RequireAuth(c fiber.Ctx) error {
	if h.AdminToken == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "ADMIN_TOKEN not configured"})
	}
	// Cookie session (browser UI) or bearer token (API clients).
	if h.Sessions.Valid(c.Cookies(sessionCookie)) {
		c.Locals("actor", "admin")
		return c.Next()
	}
	got := strings.TrimSpace(c.Get("Authorization"))
	got = strings.TrimPrefix(got, "Bearer ")
	got = strings.TrimSpace(got)
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.AdminToken)) == 1 {
		c.Locals("actor", "admin")
		return c.Next()
	}
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
}

func (h *Handler) resolveUpstream(ref string) (*model.Upstream, error) {
	ref = strings.TrimSpace(ref)
	var u model.Upstream
	if ref == "" {
		// default: oldest upstream
		if err := h.DB.Order("created_at asc").First(&u).Error; err != nil {
			return nil, err
		}
		return &u, nil
	}
	if err := h.DB.Where("id = ? OR name = ?", ref, ref).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// Audit records every admin call, including failed auth. Registered before
// RequireAuth so denials are logged too.
func (h *Handler) Audit(c fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	actor, _ := c.Locals("actor").(string)
	if actor == "" {
		actor = "unknown"
	}
	_ = h.DB.Create(&model.AuditLog{
		Source:     "admin",
		Actor:      actor,
		Method:     c.Method(),
		Path:       "/" + strings.TrimPrefix(c.Path(), "/"),
		Query:      string(c.Request().URI().QueryString()),
		Status:     c.Response().StatusCode(),
		ClientIP:   c.IP(),
		DurationMs: time.Since(start).Milliseconds(),
	}).Error
	return err
}

type createKeyInput struct {
	Name       string     `json:"name"`
	Policy     string     `json:"policy"`
	Upstream   string     `json:"upstream"`
	AllowedIPs string     `json:"allowedIPs"`
	ExpiresAt  *time.Time `json:"expiresAt"`
}

func (h *Handler) CreateKey(c fiber.Ctx) error {
	var in createKeyInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Policy = strings.TrimSpace(in.Policy)
	if in.Name == "" || in.Policy == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name and policy required"})
	}
	var p model.Policy
	if err := h.DB.Where("name = ?", in.Policy).First(&p).Error; err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "unknown policy"})
	}
	u, err := h.resolveUpstream(in.Upstream)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "unknown upstream (create one first)"})
	}
	plain, err := keys.Generate()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "key generation failed"})
	}
	allowed := keys.NormalizeAllowedIPs(in.AllowedIPs)
	if _, err := keys.ParseAllowedIPs(allowed); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid allowedIPs: " + err.Error()})
	}
	k := model.ApiKey{
		ID:         "key_" + uuid.NewString(),
		Name:       in.Name,
		KeyHash:    keys.Hash(plain),
		KeyPrefix:  keys.Prefix(plain),
		PolicyID:   p.ID,
		UpstreamID: u.ID,
		IsActive:   true,
		AllowedIPs: allowed,
		ExpiresAt:  in.ExpiresAt,
	}
	if err := h.DB.Create(&k).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
	}
	return c.Status(201).JSON(fiber.Map{
		"id": k.ID, "name": k.Name, "prefix": k.KeyPrefix,
		"policy": p.Name, "upstream": u.Name, "key": plain,
	})
}

func (h *Handler) ListKeys(c fiber.Ctx) error {
	var out []model.ApiKey
	if err := h.DB.Preload("Policy").Preload("Upstream").Order("created_at desc").Find(&out).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	res := make([]fiber.Map, 0, len(out))
	for _, k := range out {
		res = append(res, fiber.Map{
			"id": k.ID, "name": k.Name, "prefix": k.KeyPrefix,
			"policy": k.Policy.Name, "upstream": k.Upstream.Name,
			"upstreamId": k.UpstreamID, "active": k.IsActive,
			"allowedIPs": k.AllowedIPs,
			"expiresAt":  k.ExpiresAt, "lastUsedAt": k.LastUsedAt,
			"createdAt": k.CreatedAt,
		})
	}
	return c.JSON(res)
}

type updateKeyInput struct {
	Name       *string `json:"name"`
	Policy     *string `json:"policy"`
	AllowedIPs *string `json:"allowedIPs"`
	// Double pointer: absent = keep, null = clear, value = set.
	ExpiresAt **time.Time `json:"expiresAt"`
}

// UpdateKey edits name, policy, IP allowlist and expiry of a sub-key.
func (h *Handler) UpdateKey(c fiber.Ctx) error {
	var k model.ApiKey
	if err := h.DB.Where("id = ?", c.Params("id")).First(&k).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	var in updateKeyInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name must not be empty"})
		}
		k.Name = strings.TrimSpace(*in.Name)
	}
	if in.Policy != nil {
		var p model.Policy
		if err := h.DB.Where("name = ?", strings.TrimSpace(*in.Policy)).First(&p).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "unknown policy"})
		}
		k.PolicyID = p.ID
	}
	if in.AllowedIPs != nil {
		allowed := keys.NormalizeAllowedIPs(*in.AllowedIPs)
		if _, err := keys.ParseAllowedIPs(allowed); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid allowedIPs: " + err.Error()})
		}
		k.AllowedIPs = allowed
	}
	if in.ExpiresAt != nil {
		k.ExpiresAt = *in.ExpiresAt // nil clears the expiry
	}
	if err := h.DB.Save(&k).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// RotateKey replaces a sub-key with fresh random material, returning the
// plaintext once. The old value stops working immediately.
func (h *Handler) RotateKey(c fiber.Ctx) error {
	var k model.ApiKey
	if err := h.DB.Where("id = ?", c.Params("id")).First(&k).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	plain, err := keys.Generate()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "key generation failed"})
	}
	k.KeyHash = keys.Hash(plain)
	k.KeyPrefix = keys.Prefix(plain)
	if err := h.DB.Save(&k).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
	}
	return c.JSON(fiber.Map{"id": k.ID, "prefix": k.KeyPrefix, "key": plain})
}

func (h *Handler) RevokeKey(c fiber.Ctx) error {
	var k model.ApiKey
	if err := h.DB.Where("id = ?", c.Params("id")).First(&k).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	k.IsActive = false
	_ = h.DB.Save(&k).Error
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) DeleteKey(c fiber.Ctx) error {
	if err := h.DB.Where("id = ?", c.Params("id")).Delete(&model.ApiKey{}).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "delete failed"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

func upstreamView(u model.Upstream, nKeys int64) fiber.Map {
	return fiber.Map{
		"id": u.ID, "name": u.Name, "baseUrl": u.BaseURL,
		"keyHint": u.KeyHint, "active": u.IsActive, "keys": nKeys,
		"createdAt": u.CreatedAt, "updatedAt": u.UpdatedAt,
	}
}

func (h *Handler) ListUpstreams(c fiber.Ctx) error {
	var us []model.Upstream
	if err := h.DB.Order("created_at asc").Find(&us).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	res := make([]fiber.Map, 0, len(us))
	for _, u := range us {
		var n int64
		_ = h.DB.Model(&model.ApiKey{}).Where("upstream_id = ?", u.ID).Count(&n).Error
		res = append(res, upstreamView(u, n))
	}
	return c.JSON(res)
}

type upsertUpstreamInput struct {
	Name   string `json:"name"`
	GodKey string `json:"godKey"`
	Active *bool  `json:"active"`
}

func (h *Handler) CreateUpstream(c fiber.Ctx) error {
	var in upsertUpstreamInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.GodKey) == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name and godKey required"})
	}
	u, err := db.CreateUpstream(h.DB, h.EncKey, in.Name, in.GodKey)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "create failed (name taken?)"})
	}
	return c.Status(201).JSON(upstreamView(*u, 0))
}

func (h *Handler) UpdateUpstream(c fiber.Ctx) error {
	var u model.Upstream
	if err := h.DB.Where("id = ?", c.Params("id")).First(&u).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	var in upsertUpstreamInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if strings.TrimSpace(in.Name) != "" {
		u.Name = strings.TrimSpace(in.Name)
	}
	if strings.TrimSpace(in.GodKey) != "" {
		sealed, err := crypto.Seal(h.EncKey, strings.TrimSpace(in.GodKey))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "seal failed"})
		}
		u.GodKeySealed = sealed
		u.KeyHint = "…" + strings.TrimSpace(in.GodKey)[max(0, len(strings.TrimSpace(in.GodKey))-4):]
	}
	if in.Active != nil {
		u.IsActive = *in.Active
	}
	if err := h.DB.Save(&u).Error; err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "update failed (name taken?)"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) DeleteUpstream(c fiber.Ctx) error {
	var n int64
	_ = h.DB.Model(&model.ApiKey{}).Where("upstream_id = ?", c.Params("id")).Count(&n).Error
	if n > 0 {
		return c.Status(409).JSON(fiber.Map{"error": "upstream still has sub-keys"})
	}
	if err := h.DB.Where("id = ?", c.Params("id")).Delete(&model.Upstream{}).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "delete failed"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// TestUpstream performs a cheap read against sevDesk to verify the stored god key.
func (h *Handler) TestUpstream(c fiber.Ctx) error {
	var u model.Upstream
	if err := h.DB.Where("id = ?", c.Params("id")).First(&u).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	godKey, err := crypto.Open(h.EncKey, u.GodKeySealed)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "cannot decrypt god key"})
	}
	req, _ := http.NewRequest("GET", strings.TrimSuffix(u.BaseURL, "/")+"/CheckAccount?limit=1", nil)
	req.Header.Set("Authorization", godKey)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return c.JSON(fiber.Map{"ok": false, "error": "upstream unreachable"})
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return c.JSON(fiber.Map{"ok": false, "status": resp.StatusCode})
	}
	return c.JSON(fiber.Map{"ok": true, "status": resp.StatusCode})
}

type upsertPolicyInput struct {
	Name  string        `json:"name"`
	Rules []policy.Rule `json:"rules"`
}

func (h *Handler) ListPolicies(c fiber.Ctx) error {
	var ps []model.Policy
	if err := h.DB.Order("name asc").Find(&ps).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	out := make([]fiber.Map, 0, len(ps))
	for _, p := range ps {
		rules, _ := policy.Parse(p.RulesJSON)
		out = append(out, fiber.Map{"id": p.ID, "name": p.Name, "rules": rules})
	}
	return c.JSON(out)
}

func (h *Handler) UpsertPolicy(c fiber.Ctx) error {
	var in upsertPolicyInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name required"})
	}
	raw := policy.MustJSON(in.Rules)
	var p model.Policy
	if err := h.DB.Where("name = ?", in.Name).First(&p).Error; err != nil {
		p = model.Policy{ID: "pol_" + uuid.NewString(), Name: in.Name, RulesJSON: raw}
		if err := h.DB.Create(&p).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
		}
		return c.Status(201).JSON(fiber.Map{"id": p.ID, "name": p.Name})
	}
	p.RulesJSON = raw
	_ = h.DB.Save(&p).Error
	return c.JSON(fiber.Map{"id": p.ID, "name": p.Name})
}

func (h *Handler) ListAudit(c fiber.Ctx) error {
	limit := fiber.Query[int](c, "limit", 100)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := fiber.Query[int](c, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	var rows []model.AuditLog
	var total int64
	q := h.DB.Model(&model.AuditLog{})
	if v := c.Query("source"); v != "" {
		q = q.Where("source = ?", v)
	}
	if v := c.Query("keyPrefix"); v != "" {
		q = q.Where("key_prefix = ?", v)
	}
	if v := c.Query("upstream"); v != "" {
		q = q.Where("upstream_id = ?", v)
	}
	if v := fiber.Query[int](c, "status", 0); v != 0 {
		q = q.Where("status = ?", v)
	}
	_ = q.Count(&total).Error
	if err := q.Order("id desc").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	return c.JSON(fiber.Map{"total": total, "rows": rows})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- notification channels ---

var validEvents = map[string]bool{notify.EventDenied: true, notify.EventUpstreamErr: true}

func channelView(ch model.NotificationChannel, encKey []byte) fiber.Map {
	target := ""
	if raw, err := crypto.Open(encKey, ch.ConfigSealed); err == nil {
		var base struct {
			URL  string   `json:"url"`
			Host string   `json:"host"`
			To   []string `json:"to"`
		}
		if json.Unmarshal([]byte(raw), &base) == nil {
			switch {
			case base.URL != "":
				target = base.URL
			case base.Host != "":
				target = base.Host + " -> " + strings.Join(base.To, ", ")
			}
		}
	}
	var events []string
	_ = json.Unmarshal([]byte(ch.EventsJSON), &events)
	return fiber.Map{
		"id": ch.ID, "name": ch.Name, "type": ch.Type, "events": events,
		"target": target, "cooldownSeconds": ch.CooldownSeconds,
		"active": ch.IsActive, "createdAt": ch.CreatedAt,
	}
}

type upsertChannelInput struct {
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	Events          []string       `json:"events"`
	CooldownSeconds int            `json:"cooldownSeconds"`
	Config          map[string]any `json:"config"`
	Active          *bool          `json:"active"`
}

func (h *Handler) ListChannels(c fiber.Ctx) error {
	var out []model.NotificationChannel
	if err := h.DB.Order("created_at asc").Find(&out).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "query failed"})
	}
	res := make([]fiber.Map, 0, len(out))
	for _, ch := range out {
		res = append(res, channelView(ch, h.EncKey))
	}
	return c.JSON(res)
}

func (h *Handler) CreateChannel(c fiber.Ctx) error {
	var in upsertChannelInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name required"})
	}
	cfg, err := normalizeChannelConfig(in.Type, in.Config)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	for _, e := range in.Events {
		if !validEvents[e] {
			return c.Status(400).JSON(fiber.Map{"error": "unknown event: " + e})
		}
	}
	if len(in.Events) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "at least one event required"})
	}
	sealed, err := crypto.Seal(h.EncKey, cfg)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "seal failed"})
	}
	ev, _ := json.Marshal(in.Events)
	cd := in.CooldownSeconds
	if cd <= 0 {
		cd = 300
	}
	ch := model.NotificationChannel{
		ID:              "ch_" + uuid.NewString(),
		Name:            in.Name,
		Type:            in.Type,
		EventsJSON:      string(ev),
		ConfigSealed:    sealed,
		CooldownSeconds: cd,
		IsActive:        true,
	}
	if in.Active != nil {
		ch.IsActive = *in.Active
	}
	if err := h.DB.Create(&ch).Error; err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "create failed (name taken?)"})
	}
	return c.Status(201).JSON(channelView(ch, h.EncKey))
}

func (h *Handler) UpdateChannel(c fiber.Ctx) error {
	var ch model.NotificationChannel
	if err := h.DB.Where("id = ?", c.Params("id")).First(&ch).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	var in upsertChannelInput
	if err := c.Bind().Body(&in); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid json"})
	}
	if in.Events != nil {
		for _, e := range in.Events {
			if !validEvents[e] {
				return c.Status(400).JSON(fiber.Map{"error": "unknown event: " + e})
			}
		}
		ev, _ := json.Marshal(in.Events)
		ch.EventsJSON = string(ev)
	}
	if in.CooldownSeconds > 0 {
		ch.CooldownSeconds = in.CooldownSeconds
	}
	if in.Active != nil {
		ch.IsActive = *in.Active
	}
	if err := h.DB.Save(&ch).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "persist failed"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) DeleteChannel(c fiber.Ctx) error {
	if err := h.DB.Where("id = ?", c.Params("id")).Delete(&model.NotificationChannel{}).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "delete failed"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// TestChannel fires a test event, bypassing cooldowns.
func (h *Handler) TestChannel(c fiber.Ctx) error {
	var ch model.NotificationChannel
	if err := h.DB.Where("id = ?", c.Params("id")).First(&ch).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	n := notify.New(h.DB, h.EncKey)
	p := notify.Payload{Event: notify.EventTest, Method: "GET", Path: "/api/v1/CheckAccount", Status: 200}
	if err := n.Send(ch, p); err != nil {
		return c.JSON(fiber.Map{"ok": false, "error": err.Error()})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// normalizeChannelConfig validates type-specific config and returns canonical JSON.
// Secrets are never returned; store only.
func normalizeChannelConfig(typ string, raw map[string]any) (string, error) {
	str := func(m map[string]any, k string) string {
		v, _ := m[k].(string)
		return strings.TrimSpace(v)
	}
	switch typ {
	case "webhook":
		w := notify.WebhookConfig{URL: str(raw, "url"), Secret: str(raw, "secret")}
		if err := w.Validate(); err != nil {
			return "", err
		}
		b, _ := json.Marshal(w)
		return string(b), nil
	case "telegram":
		t := notify.TelegramConfig{BotToken: str(raw, "botToken"), ChatID: str(raw, "chatId")}
		if err := t.Validate(); err != nil {
			return "", err
		}
		b, _ := json.Marshal(t)
		return string(b), nil
	case "smtp":
		port := 0
		switch v := raw["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		to := []string{}
		switch v := raw["to"].(type) {
		case string:
			for _, t := range strings.Split(v, ",") {
				if t = strings.TrimSpace(t); t != "" {
					to = append(to, t)
				}
			}
		case []any:
			for _, t := range v {
				if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
					to = append(to, strings.TrimSpace(s))
				}
			}
		}
		s := notify.SMTPConfig{
			Host: str(raw, "host"), Port: port,
			Username: str(raw, "username"), Password: str(raw, "password"),
			From: str(raw, "from"), To: to,
		}
		if err := s.Validate(); err != nil {
			return "", err
		}
		b, _ := json.Marshal(s)
		return string(b), nil
	default:
		return "", fmt.Errorf("unknown channel type %q (webhook|smtp|telegram)", typ)
	}
}

// Stats returns dashboard counters. Expensive scans are capped by time range.
func (h *Handler) Stats(c fiber.Ctx) error {
	var keysTotal, keysActive, upsTotal, upsActive, chTotal, chActive, auditTotal, denied24, upstreamErr24 int64
	since := time.Now().Add(-24 * time.Hour)
	_ = h.DB.Model(&model.ApiKey{}).Count(&keysTotal).Error
	_ = h.DB.Model(&model.ApiKey{}).Where("is_active = ?", true).Count(&keysActive).Error
	_ = h.DB.Model(&model.Upstream{}).Count(&upsTotal).Error
	_ = h.DB.Model(&model.Upstream{}).Where("is_active = ?", true).Count(&upsActive).Error
	_ = h.DB.Model(&model.NotificationChannel{}).Count(&chTotal).Error
	_ = h.DB.Model(&model.NotificationChannel{}).Where("is_active = ?", true).Count(&chActive).Error
	_ = h.DB.Model(&model.AuditLog{}).Count(&auditTotal).Error
	_ = h.DB.Model(&model.AuditLog{}).Where("created_at >= ? AND status IN ?", since, []int{401, 403}).Count(&denied24).Error
	_ = h.DB.Model(&model.AuditLog{}).Where("created_at >= ? AND status >= 500", since).Count(&upstreamErr24).Error
	return c.JSON(fiber.Map{
		"keys":      fiber.Map{"total": keysTotal, "active": keysActive},
		"upstreams": fiber.Map{"total": upsTotal, "active": upsActive},
		"channels":  fiber.Map{"total": chTotal, "active": chActive},
		"audit":     fiber.Map{"total": auditTotal, "denied24h": denied24, "upstreamErrors24h": upstreamErr24},
	})
}
