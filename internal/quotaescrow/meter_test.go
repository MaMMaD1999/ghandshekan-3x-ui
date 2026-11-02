//go:build cgo

package quotaescrow

import (
	"path/filepath"
	"testing"
)

func TestActivationMetersAggregateAliasesWithoutRebillingBaseline(t *testing.T) {
	p, k := fixture(t)
	p.AlreadyBilled = 600
	p.Grants = map[string]int64{"de": 200, "at": 100, "nl": 100}
	path := filepath.Join(t.TempDir(), "meter.db")
	s, close := openStore(t, path)
	if err := s.db.AutoMigrate(&Meter{}); err != nil {
		t.Fatal(err)
	}
	meters := []Meter{{Subscription: p.Subscription, Epoch: p.Epoch, Owner: "at", Source: "phone-generation-1", Watermark: 400}, {Subscription: p.Subscription, Epoch: p.Epoch, Owner: "at", Source: "laptop-generation-1", Watermark: 200}}
	if err := s.Activate(p, meters); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := s.ObserveMeter(p.Subscription, "at", meters[0].Source, k["at"], 440); err != nil {
			t.Fatal(err)
		}
		if err := s.ObserveMeter(p.Subscription, "at", meters[1].Source, k["at"], 230); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 670)
	close()
	s, close = openStore(t, path)
	defer close()
	if err = s.ObserveMeter(p.Subscription, "at", meters[0].Source, k["at"], 440); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Admission(p.Subscription, "at", 100); err != nil || n != 30 {
		t.Fatal(n, err)
	}
	if n, err := s.Admission(p.Subscription, "at", 5000); err != nil || n != 0 {
		t.Fatal("expiry needs no master", n, err)
	}
	if err = s.ObserveMeter(p.Subscription, "at", meters[0].Source, k["at"], 1); err == nil {
		t.Fatal("reset counter accepted")
	}
	if err = s.ObserveMeter(p.Subscription, "at", meters[0].Source, k["at"], 480); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Admission(p.Subscription, "at", 100); err != nil || n != 0 {
		t.Fatal("exhausted allowance still admitted", n, err)
	}
	l, err = s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 710)
}

func TestMeterWatermarkFailureRollsBackLedger(t *testing.T) {
	p, k := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "meter.db"))
	defer close()
	if err := s.db.AutoMigrate(&Meter{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(p, []Meter{{Subscription: p.Subscription, Epoch: p.Epoch, Owner: "at", Source: "local", Watermark: 20}}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("CREATE TRIGGER fail_watermark BEFORE UPDATE ON quota_escrow_meters BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveMeter(p.Subscription, "at", "local", k["at"], 40); err == nil {
		t.Fatal("failed write accepted")
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 0)
	if err = s.db.Exec("DROP TRIGGER fail_watermark").Error; err != nil {
		t.Fatal(err)
	}
	if err = s.ObserveMeter(p.Subscription, "at", "local", k["at"], 40); err != nil {
		t.Fatal(err)
	}
	l, err = s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 20)
}
