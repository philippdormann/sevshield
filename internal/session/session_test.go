package session

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"sevshield/internal/model"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AutoMigrate(&model.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSession(t *testing.T) {
	s := New(testDB(t), time.Hour)
	id, err := s.Create()
	if err != nil || !s.Valid(id) {
		t.Fatalf("fresh session must be valid: %v", err)
	}
	if s.Valid("") || s.Valid("bogus") {
		t.Error("empty/bogus must be invalid")
	}
	s.Revoke(id)
	if s.Valid(id) {
		t.Error("revoked session must be invalid")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := New(testDB(t), 50*time.Millisecond)
	id, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if s.Valid(id) {
		t.Error("expired session must be invalid")
	}
}
