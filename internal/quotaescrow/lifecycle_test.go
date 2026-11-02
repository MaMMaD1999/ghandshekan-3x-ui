//go:build cgo

package quotaescrow

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFencedRenewalPreservesConsumptionAndRejectsMissingMember(t *testing.T) {
	p, keys := fixture(t)
	stores := map[string]*Store{}
	proofs := []FreezeProof{}
	for _, owner := range []string{"de", "at", "nl"} {
		s, close := openStore(t, filepath.Join(t.TempDir(), owner+".db"))
		t.Cleanup(close)
		if err := s.db.AutoMigrate(&Meter{}, &EpochArchive{}); err != nil {
			t.Fatal(err)
		}
		if err := s.Activate(p, []Meter{{Subscription: p.Subscription, Owner: owner, Source: "local", Epoch: p.Epoch, Watermark: 50}}); err != nil {
			t.Fatal(err)
		}
		if err := s.ObserveMeter(p.Subscription, owner, "local", keys[owner], 150); err != nil {
			t.Fatal(err)
		}
		if err := s.BeginTransition(p.Subscription, "reset-2", "operation-1"); err != nil {
			t.Fatal(err)
		}
		proof, err := s.Freeze(p.Subscription, owner, "reset-2", "operation-1", keys[owner])
		if err != nil {
			t.Fatal(err)
		}
		again, err := s.Freeze(p.Subscription, owner, "reset-2", "operation-1", keys[owner])
		if err != nil || !reflect.DeepEqual(again, proof) {
			t.Fatal("freeze retry changed final proof", err)
		}
		if n, err := s.Admission(p.Subscription, owner, 100); n != 0 || !errors.Is(err, ErrFrozen) {
			t.Fatal(n, err)
		}
		if err := s.ObserveMeter(p.Subscription, owner, "local", keys[owner], 151); !errors.Is(err, ErrFrozen) {
			t.Fatal("frozen meter changed", err)
		}
		if _, err := s.Transfer(p.Subscription, owner, keys[owner], 1, "at", 100); !errors.Is(err, ErrFrozen) {
			t.Fatal("frozen owner transferred credit", err)
		}
		stores[owner] = s
		proofs = append(proofs, proof)
	}
	next := clone(p)
	next.Epoch = "reset-2"
	next.Limit = 1300
	next.AlreadyBilled = 300
	for _, owner := range []string{"de", "at", "nl"} {
		s := stores[owner]
		meters := []Meter{{Subscription: p.Subscription, Owner: owner, Source: "local", Epoch: next.Epoch, Watermark: 150}}
		if err := s.CommitTransition(next, "renew", proofs[:2], meters); err == nil {
			t.Fatal("missing member's rights reissued")
		}
		bad := clone(proofs)
		bad[0].NextEpoch = "another"
		if err := s.CommitTransition(next, "renew", bad, meters); err == nil {
			t.Fatal("wrong epoch proof accepted")
		}
		bad = clone(proofs)
		bad[0].Signature[0] ^= 1
		if err := s.CommitTransition(next, "renew", bad, meters); err == nil {
			t.Fatal("tampered proof accepted")
		}
		if err := s.CommitTransition(next, "renew", proofs, meters); err != nil {
			t.Fatal(err)
		}
		l, err := s.Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		assertBilled(t, l, 300)
		if err := s.ObserveMeter(p.Subscription, owner, "local", keys[owner], 160); err != nil {
			t.Fatal(err)
		}
		l, err = s.Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		assertBilled(t, l, 310)
		if err := s.CommitTransition(next, "renew", proofs, meters); err != nil {
			t.Fatal("commit receipt retry failed", err)
		}
		l, err = s.Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		assertBilled(t, l, 310)
		if err := s.Merge(p.Subscription, proofs[0].Rows); !errors.Is(err, ErrEpoch) {
			t.Fatal("old report accepted", err)
		}
	}
}

func TestFencedResetIsAtomicAndDoesNotReuseOldEpoch(t *testing.T) {
	p, keys := fixture(t)
	// One-member case isolates commit/rollback behavior from transport.
	p.Keys = map[string][]byte{"de": p.Keys["de"]}
	p.Grants = map[string]int64{"de": 1000}
	s, close := openStore(t, filepath.Join(t.TempDir(), "reset.db"))
	defer close()
	if err := s.db.AutoMigrate(&Meter{}, &EpochArchive{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(p, []Meter{{Subscription: p.Subscription, Owner: "de", Source: "old", Epoch: p.Epoch}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveMeter(p.Subscription, "de", "old", keys["de"], 250); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTransition(p.Subscription, "reset-2", "op-reset"); err != nil {
		t.Fatal(err)
	}
	proof, err := s.Freeze(p.Subscription, "de", "reset-2", "op-reset", keys["de"])
	if err != nil {
		t.Fatal(err)
	}
	next := clone(p)
	next.Epoch = "reset-2"
	meters := []Meter{{Subscription: p.Subscription, Owner: "de", Source: "new", Epoch: next.Epoch}}
	if err := s.db.Exec("CREATE TRIGGER fail_new_meter BEFORE INSERT ON quota_escrow_meters BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.CommitTransition(next, "reset", []FreezeProof{proof}, meters); err == nil {
		t.Fatal("partial reset committed")
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 250)
	if n, err := s.Admission(p.Subscription, "de", 100); n != 0 || !errors.Is(err, ErrFrozen) {
		t.Fatal(n, err)
	}
	if err := s.db.Exec("DROP TRIGGER fail_new_meter").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.CommitTransition(next, "reset", []FreezeProof{proof}, meters); err != nil {
		t.Fatal(err)
	}
	l, err = s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 0)
	if err := s.BeginTransition(p.Subscription, p.Epoch, "reuse"); err != nil {
		t.Fatal(err)
	}
	proof, err = s.Freeze(p.Subscription, "de", p.Epoch, "reuse", keys["de"])
	if err != nil {
		t.Fatal(err)
	}
	meters[0].Epoch = p.Epoch
	if err := s.CommitTransition(p, "reset", []FreezeProof{proof}, meters); err == nil {
		t.Fatal("old epoch resurrected")
	}
}

func TestTransitionBarrierSurvivesRestartAndAllowsFinalSettlement(t *testing.T) {
	p, keys := fixture(t)
	path := filepath.Join(t.TempDir(), "barrier.db")
	s, closeStore := openStore(t, path)
	if err := s.db.AutoMigrate(&Meter{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(p, []Meter{{Subscription: p.Subscription, Owner: "de", Source: "local", Epoch: p.Epoch}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Freeze(p.Subscription, "de", "next", "op", keys["de"]); err == nil {
		t.Fatal("signed final proof without durable admission barrier")
	}
	if err := s.BeginTransition(p.Subscription, "next", "op"); err != nil {
		t.Fatal(err)
	}
	closeStore()
	s, closeStore = openStore(t, path)
	defer closeStore()
	if n, err := s.Admission(p.Subscription, "de", 100); n != 0 || !errors.Is(err, ErrFrozen) {
		t.Fatal("reopened old epoch after restart", n, err)
	}
	if err := s.BeginTransition(p.Subscription, "next", "op"); err != nil {
		t.Fatal("barrier retry failed", err)
	}
	if err := s.BeginTransition(p.Subscription, "other", "op"); !errors.Is(err, ErrFrozen) {
		t.Fatal("transition target changed", err)
	}
	if _, err := s.Transfer(p.Subscription, "de", keys["de"], 1, "at", 100); !errors.Is(err, ErrFrozen) {
		t.Fatal("transferred rights while draining", err)
	}
	if err := s.ObserveMeter(p.Subscription, "de", "local", keys["de"], 25); err != nil {
		t.Fatal("final drained traffic lost", err)
	}
	proof, err := s.Freeze(p.Subscription, "de", "next", "op", keys["de"])
	if err != nil {
		t.Fatal(err)
	}
	l, _ := s.Load(p.Subscription)
	assertBilled(t, l, 25)
	if len(proof.Rows) != 1 || proof.Rows[0].Row.Used != 25 {
		t.Fatal("final proof omitted drained consumption", proof)
	}
}
