package session

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"gorm.io/gorm"

	"sevshield/internal/model"
)

// Store is a DB-backed session registry. Only random IDs travel in the
// httpOnly cookie, so sessions survive restarts.
type Store struct {
	db  *gorm.DB
	ttl time.Duration
}

func New(db *gorm.DB, ttl time.Duration) *Store {
	return &Store{db: db, ttl: ttl}
}

// Create issues a new session ID and purges expired ones.
func (s *Store) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	now := time.Now()
	if err := s.db.Create(&model.AdminSession{ID: id, ExpiresAt: now.Add(s.ttl)}).Error; err != nil {
		return "", err
	}
	_ = s.db.Where("expires_at < ?", now).Delete(&model.AdminSession{}).Error
	return id, nil
}

// Valid reports whether id is a live session and slides its expiry.
func (s *Store) Valid(id string) bool {
	if id == "" {
		return false
	}
	var sess model.AdminSession
	if err := s.db.Where("id = ?", id).First(&sess).Error; err != nil {
		return false
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) {
		_ = s.db.Delete(&model.AdminSession{}, "id = ?", id).Error
		return false
	}
	_ = s.db.Model(&model.AdminSession{}).Where("id = ?", id).Update("expires_at", now.Add(s.ttl)).Error
	return true
}

// Revoke deletes a session.
func (s *Store) Revoke(id string) {
	if id == "" {
		return
	}
	_ = s.db.Delete(&model.AdminSession{}, "id = ?", id).Error
}
