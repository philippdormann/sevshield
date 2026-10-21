package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"sevshield/internal/crypto"
	"sevshield/internal/model"
)

// Events emitted by the proxy.
const (
	EventDenied      = "denied"         // 401/403: bad key, expired, policy or IP denial
	EventUpstreamErr = "upstream_error" // upstream unreachable, 5xx, disabled upstream
	EventTest        = "test"
)

// Payload carries one alert.
type Payload struct {
	Time       time.Time `json:"time"`
	Event      string    `json:"event"`
	KeyPrefix  string    `json:"keyPrefix,omitempty"`
	ApiKeyID   string    `json:"apiKeyId,omitempty"`
	UpstreamID string    `json:"upstreamId,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	ClientIP   string    `json:"clientIp,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

func (w WebhookConfig) Validate() error {
	if strings.TrimSpace(w.URL) == "" {
		return fmt.Errorf("url required")
	}
	if !strings.HasPrefix(w.URL, "http://") && !strings.HasPrefix(w.URL, "https://") {
		return fmt.Errorf("url must be http(s)")
	}
	return nil
}

type SMTPConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

func (s SMTPConfig) Addr() string {
	port := s.Port
	if port == 0 {
		port = 587
	}
	return fmt.Sprintf("%s:%d", s.Host, port)
}

func (s SMTPConfig) Validate() error {
	if strings.TrimSpace(s.Host) == "" {
		return fmt.Errorf("host required")
	}
	if strings.TrimSpace(s.From) == "" || !strings.Contains(s.From, "@") {
		return fmt.Errorf("valid from address required")
	}
	if len(s.To) == 0 {
		return fmt.Errorf("at least one recipient required")
	}
	return nil
}

type TelegramConfig struct {
	BotToken string `json:"botToken"`
	ChatID   string `json:"chatId"`
}

func (t TelegramConfig) Validate() error {
	if strings.TrimSpace(t.BotToken) == "" {
		return fmt.Errorf("botToken required")
	}
	if strings.TrimSpace(t.ChatID) == "" {
		return fmt.Errorf("chatId required")
	}
	return nil
}

// Notifier fans events out to active channels with per-channel cooldown.
type Notifier struct {
	DB     *gorm.DB
	EncKey []byte
	HTTP   *http.Client

	mu   sync.Mutex
	last map[string]time.Time
}

func New(db *gorm.DB, encKey []byte) *Notifier {
	return &Notifier{
		DB:     db,
		EncKey: encKey,
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		last:   map[string]time.Time{},
	}
}

func wanted(eventsJSON, event string) bool {
	var ev []string
	if err := json.Unmarshal([]byte(eventsJSON), &ev); err != nil {
		return false
	}
	for _, e := range ev {
		if e == event {
			return true
		}
	}
	return false
}

// Fire delivers event to all matching channels, honouring cooldowns.
// It never blocks the caller.
func (n *Notifier) Fire(event string, p Payload) {
	if n == nil || n.DB == nil {
		return
	}
	p.Event = event
	p.Time = time.Now()
	var channels []model.NotificationChannel
	if err := n.DB.Where("is_active = ?", true).Find(&channels).Error; err != nil {
		return
	}
	for _, ch := range channels {
		if !wanted(ch.EventsJSON, event) {
			continue
		}
		n.mu.Lock()
		last := n.last[ch.ID]
		cd := time.Duration(ch.CooldownSeconds) * time.Second
		if cd < 0 {
			cd = 0
		}
		if !last.IsZero() && time.Since(last) < cd {
			n.mu.Unlock()
			continue
		}
		n.last[ch.ID] = time.Now()
		n.mu.Unlock()
		go n.deliver(ch, p)
	}
}

// Send bypasses cooldowns (used by the admin test endpoint).
func (n *Notifier) Send(ch model.NotificationChannel, p Payload) error {
	cfg, err := crypto.Open(n.EncKey, ch.ConfigSealed)
	if err != nil {
		return err
	}
	switch ch.Type {
	case "webhook":
		var w WebhookConfig
		if err := json.Unmarshal([]byte(cfg), &w); err != nil {
			return err
		}
		if err := w.Validate(); err != nil {
			return err
		}
		return sendWebhook(n.HTTP, w, p)
	case "smtp":
		var s SMTPConfig
		if err := json.Unmarshal([]byte(cfg), &s); err != nil {
			return err
		}
		if err := s.Validate(); err != nil {
			return err
		}
		return sendMail(s, p)
	case "telegram":
		var t TelegramConfig
		if err := json.Unmarshal([]byte(cfg), &t); err != nil {
			return err
		}
		if err := t.Validate(); err != nil {
			return err
		}
		return sendTelegram(n.HTTP, t, p)
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}
}

func (n *Notifier) deliver(ch model.NotificationChannel, p Payload) {
	if err := n.Send(ch, p); err != nil {
		// Delivery failures must never break proxying; they surface in logs.
		fmt.Printf("notify %s (%s) failed: %v\n", ch.Name, ch.Type, err)
	}
}

func sendWebhook(client *http.Client, w WebhookConfig, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sevshield-Event", p.Event)
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-Sevshield-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func subject(p Payload) string {
	switch p.Event {
	case EventDenied:
		return fmt.Sprintf("[sevshield] denied %s %s (%s)", p.Method, p.Path, p.KeyPrefix)
	case EventUpstreamErr:
		return fmt.Sprintf("[sevshield] upstream error %s %s", p.Method, p.Path)
	default:
		return fmt.Sprintf("[sevshield] %s", p.Event)
	}
}

func telegramText(p Payload) string {
	var b strings.Builder
	b.WriteString("<b>" + subject(p) + "</b>\n")
	fmt.Fprintf(&b, "time: %s\n", p.Time.Format(time.RFC3339))
	if p.KeyPrefix != "" {
		fmt.Fprintf(&b, "key: %s…\n", p.KeyPrefix)
	}
	if p.UpstreamID != "" {
		fmt.Fprintf(&b, "upstream: %s\n", p.UpstreamID)
	}
	if p.Method != "" {
		fmt.Fprintf(&b, "request: %s %s\n", p.Method, p.Path)
	}
	fmt.Fprintf(&b, "status: %d\n", p.Status)
	if p.ClientIP != "" {
		fmt.Fprintf(&b, "client: %s\n", p.ClientIP)
	}
	if p.Error != "" {
		fmt.Fprintf(&b, "error: %s\n", p.Error)
	}
	return b.String()
}

func sendTelegram(client *http.Client, t TelegramConfig, p Payload) error {
	body, _ := json.Marshal(map[string]string{
		"chat_id":    strings.TrimSpace(t.ChatID),
		"text":       telegramText(p),
		"parse_mode": "HTML",
	})
	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+strings.TrimSpace(t.BotToken)+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned %d", resp.StatusCode)
	}
	return nil
}

func sendMail(s SMTPConfig, p Payload) error {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", s.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(s.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject(p))
	fmt.Fprintf(&b, "Date: %s\r\n", p.Time.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	body, _ := json.MarshalIndent(p, "", "  ")
	b.Write(body)

	host, _, err := net.SplitHostPort(s.Addr())
	if err != nil {
		return err
	}
	if s.Port == 465 {
		return sendImplicitTLS(s, []byte(b.String()))
	}
	c, err := smtp.Dial(s.Addr())
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if s.Username != "" {
		auth := smtp.PlainAuth("", s.Username, s.Password, host)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := c.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(b.String())); err != nil {
		return err
	}
	return w.Close()
}

func sendImplicitTLS(s SMTPConfig, msg []byte) error {
	host, _, err := net.SplitHostPort(s.Addr())
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", s.Addr(), &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := c.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
