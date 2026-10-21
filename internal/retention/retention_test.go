package retention

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
	if err := g.AutoMigrate(&model.AppSetting{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRetentionDefaultUnlimited(t *testing.T) {
	days, err := GetDays(testDB(t))
	if err != nil || days != 0 {
		t.Fatalf("missing row must default to unlimited: days=%d err=%v", days, err)
	}
}

func TestRetentionSetGetAndValidation(t *testing.T) {
	db := testDB(t)
	if err := SetDays(db, 30); err != nil {
		t.Fatal(err)
	}
	days, _ := GetDays(db)
	if days != 30 {
		t.Fatalf("got %d, want 30", days)
	}
	if err := SetDays(db, 0); err != nil {
		t.Fatal(err)
	}
	if days, _ := GetDays(db); days != 0 {
		t.Fatalf("got %d, want 0 (unlimited)", days)
	}
	for _, bad := range []int{-1, MaxDays + 1} {
		if err := SetDays(db, bad); err == nil {
			t.Fatalf("SetDays(%d) must be rejected", bad)
		}
	}
}

func TestPurgeKeepsRecentDeletesOld(t *testing.T) {
	db := testDB(t)
	old := model.AuditLog{Method: "GET", Path: "/old", Status: 200, CreatedAt: time.Now().AddDate(0, 0, -60)}
	recent := model.AuditLog{Method: "GET", Path: "/recent", Status: 200, CreatedAt: time.Now()}
	if err := db.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&recent).Error; err != nil {
		t.Fatal(err)
	}
	n, err := Purge(db, 30)
	if err != nil || n != 1 {
		t.Fatalf("purge must delete exactly the old row: n=%d err=%v", n, err)
	}
	var left int64
	_ = db.Model(&model.AuditLog{}).Count(&left).Error
	if left != 1 {
		t.Fatalf("one row must remain, got %d", left)
	}
	if n, _ := Purge(db, 0); n != 0 {
		t.Fatal("days<=0 must be a no-op")
	}
}
