//go:build cgo

package quotaescrow

import (
	"path/filepath"
	"testing"
)

func TestExchangeDurableDuplicateDeliveryAndFreshReceipt(t *testing.T) {
	p, k := fixture(t)
	a, ca := openStore(t, filepath.Join(t.TempDir(), "a.db"))
	defer ca()
	b, cb := openStore(t, filepath.Join(t.TempDir(), "b.db"))
	defer cb()
	for _, s := range []*Store{a, b} {
		if err := s.Create(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Observe(p.Subscription, "at", k["at"], 120, 100); err != nil {
		t.Fatal(err)
	}
	l, _ := a.Load(p.Subscription)
	request, err := NewExchange(p, "at", "nl", k["at"], l.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var receipt SignedExchange
	for i := 0; i < 5; i++ {
		receipt, err = b.ReceiveExchange("nl", k["nl"], request)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.AcceptReceipt(request, receipt); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*Store{a, b} {
		got, e := s.Load(p.Subscription)
		if e != nil {
			t.Fatal(e)
		}
		assertBilled(t, got, 120)
	}
	next, err := NewExchange(p, "at", "nl", k["at"], l.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if a.AcceptReceipt(next, receipt) == nil {
		t.Fatal("stale receipt accepted as new delivery")
	}
	forged := clone(receipt)
	forged.Message.From = "de"
	if a.AcceptReceipt(request, forged) == nil {
		t.Fatal("relay impersonated destination")
	}
	changed := clone(request)
	changed.Message.To = "de"
	if _, err = b.ReceiveExchange("de", k["de"], changed); err == nil {
		t.Fatal("modified audience accepted")
	}
	if _, err = b.ReceiveExchange("de", k["de"], request); err == nil {
		t.Fatal("wrong recipient accepted")
	}
}

func TestExchangeFailedCommitCannotAcknowledge(t *testing.T) {
	p, k := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "quota.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	l := ledger(t, p)
	r, err := l.Observe("at", k["at"], 100)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewExchange(p, "at", "nl", k["at"], []SignedRow{r})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.db.Exec("CREATE TRIGGER fail_exchange BEFORE UPDATE ON quota_escrow_states BEGIN SELECT RAISE(ABORT, 'disk full'); END;").Error; err != nil {
		t.Fatal(err)
	}
	receipt, err := s.ReceiveExchange("nl", k["nl"], request)
	if err == nil || len(receipt.Signature) != 0 {
		t.Fatal("uncommitted receipt escaped")
	}
	got, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, got, 0)
}
