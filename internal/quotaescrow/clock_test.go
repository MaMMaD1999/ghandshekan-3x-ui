//go:build cgo

package quotaescrow

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestClockGuardRestartRollbackAndMissingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.db")
	s, closeDB := openStore(t, path)
	if err := s.db.AutoMigrate(&ClockState{}); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1800000000, 0)
	guard := new(ClockGuard)
	if _, err := guard.Unix(s.db, base); err == nil {
		t.Fatal("missing clock silently initialized")
	}
	if err := InitializeClock(s.db, base); err != nil {
		t.Fatal(err)
	}
	if got, err := guard.Unix(s.db, base.Add(10*time.Second)); err != nil || got != base.Unix()+10 {
		t.Fatal(got, err)
	}
	closeDB()
	s, closeDB = openStore(t, path)
	defer closeDB()
	guard = new(ClockGuard)
	if _, err := guard.Unix(s.db, base); !errors.Is(err, ErrClockRollback) {
		t.Fatal("restart allowed rollback", err)
	}
	if got, err := guard.Unix(s.db, base.Add(9*time.Second)); err != nil || got != base.Unix()+10 {
		t.Fatal(got, err)
	}
	// Small corrections cannot stop time: elapsed time advances from the floor.
	if got, err := guard.Unix(s.db, base.Add(14*time.Second)); err != nil || got != base.Unix()+15 {
		t.Fatal(got, err)
	}
	if err := InitializeClock(s.db, base); err != nil {
		t.Fatal(err)
	}
	if _, err := new(ClockGuard).Unix(s.db, base); !errors.Is(err, ErrClockRollback) {
		t.Fatal("reinitialization reset clock", err)
	}
}

func TestClockGuardFailedCommitCannotAuthorizeAdmission(t *testing.T) {
	s, closeDB := openStore(t, filepath.Join(t.TempDir(), "clock.db"))
	defer closeDB()
	if err := s.db.AutoMigrate(&ClockState{}); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1800000000, 0)
	if err := InitializeClock(s.db, base); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("CREATE TRIGGER fail_clock BEFORE UPDATE ON quota_escrow_clock BEGIN SELECT RAISE(ABORT, 'disk error'); END;").Error; err != nil {
		t.Fatal(err)
	}
	guard := new(ClockGuard)
	if got, err := guard.Unix(s.db, base.Add(time.Second)); err == nil || got != 0 {
		t.Fatal(got, err)
	}
	if !guard.base.IsZero() {
		t.Fatal("failed write advanced in-memory authority")
	}
}
