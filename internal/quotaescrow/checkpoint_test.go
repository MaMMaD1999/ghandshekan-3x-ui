//go:build cgo

package quotaescrow

import (
	"path/filepath"
	"testing"
)

func TestCheckpointRejectsHigherRevisionWithRegressedSignedCounters(t *testing.T) {
	p, keys := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "checkpoint.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	var original Record
	s.db.First(&original, "subscription = ?", p.Subscription)
	if err := s.Observe(p.Subscription, "de", keys["de"], 100, 100); err != nil {
		t.Fatal(err)
	}
	var current Record
	s.db.First(&current, "subscription = ?", p.Subscription)
	if err := ValidateCheckpointAdvance(original, current, nil); err != nil {
		t.Fatal(err)
	}
	forged := original
	forged.Revision = current.Revision + 1
	if err := ValidateCheckpointAdvance(current, forged, nil); err == nil {
		t.Fatal("revision hid usage rollback")
	}
	if err := s.BeginTransition(p.Subscription, "epoch-2", "reset-1"); err != nil {
		t.Fatal(err)
	}
	var paused Record
	s.db.First(&paused, "subscription = ?", p.Subscription)
	if err := ValidateCheckpointAdvance(current, paused, nil); err != nil {
		t.Fatal(err)
	}
	forged = current
	forged.Revision = paused.Revision + 1
	if err := ValidateCheckpointAdvance(paused, forged, nil); err == nil {
		t.Fatal("durable pause disappeared")
	}
}
