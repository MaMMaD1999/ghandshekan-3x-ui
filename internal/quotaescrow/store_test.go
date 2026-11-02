//go:build cgo

package quotaescrow

import (
	"path/filepath"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openStore(t *testing.T, path string) (*Store, func()) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=10000&_journal_mode=WAL&_synchronous=FULL"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err = db.AutoMigrate(&Record{}); err != nil {
		t.Fatal(err)
	}
	return NewStore(db), func() { _ = sqlDB.Close() }
}
func TestDurableRestartDoesNotRestoreSpentOrTransferredRights(t *testing.T) {
	p, k := fixture(t)
	path := filepath.Join(t.TempDir(), "quota.db")
	s, close := openStore(t, path)
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transfer(p.Subscription, "de", k["de"], 200, "at", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.Observe(p.Subscription, "at", k["at"], 450, 100); err != nil {
		t.Fatal(err)
	}
	close()
	s, close = openStore(t, path)
	defer close()
	for i := 0; i < 10; i++ {
		if err := s.Observe(p.Subscription, "at", k["at"], 450, 100); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 450)
	if n, _ := l.Available("de", 100); n != 200 {
		t.Fatal(n)
	}
	if err = s.Observe(p.Subscription, "at", k["at"], 1, 100); err == nil {
		t.Fatal("meter reset silently accepted")
	}
	p.Epoch = "new-epoch"
	if err = s.Create(p); err == nil {
		t.Fatal("unfenced reset overwrote live grants")
	}
}
func TestFailedCommitNeverReturnsTransferOrConsumesQuota(t *testing.T) {
	p, k := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "quota.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("CREATE TRIGGER reject_quota_update BEFORE UPDATE ON quota_escrow_states BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	row, err := s.Transfer(p.Subscription, "de", k["de"], 100, "at", 100)
	if err == nil || row.Row.Sequence != 0 {
		t.Fatal("uncommitted transfer escaped")
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := l.Available("de", 100); n != 400 {
		t.Fatal(n)
	}
	assertBilled(t, l, 0)
}

func TestConcurrentTransferRequestsCannotSpendSameGrant(t *testing.T) {
	p, k := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "quota.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { _, err := s.Transfer(p.Subscription, "de", k["de"], 100, "at", 100); results <- err }()
	}
	success := 0
	for i := 0; i < 16; i++ {
		if <-results == nil {
			success++
		}
	}
	if success != 4 {
		t.Fatalf("committed %d transfers, expected exactly four", success)
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 0)
	if n, _ := l.Available("de", 100); n != 0 {
		t.Fatal(n)
	}
	if n, _ := l.Available("at", 100); n != 700 {
		t.Fatal(n)
	}
}
