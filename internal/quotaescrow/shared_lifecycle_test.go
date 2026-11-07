//go:build cgo

package quotaescrow

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
)

func rollingFixture(t *testing.T) (Policy, map[string]ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	p, keys := fixture(t)
	pub, authority, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Mode, p.Version, p.ResetGeneration, p.Authority = "shared", 1, 1, pub
	p.Manager = "de"
	for owner := range p.Grants {
		p.Grants[owner] = 0
	}
	return p, keys, authority
}

func rollingStore(t *testing.T, p Policy, name string) *Store {
	t.Helper()
	s, close := openStore(t, filepath.Join(t.TempDir(), name+".db"))
	t.Cleanup(close)
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	return s
}

func applyRolling(t *testing.T, s *Store, owner string, key ed25519.PrivateKey, updates ...PolicyUpdate) {
	t.Helper()
	var before, paused, after Record
	if err := s.db.First(&before).Error; err != nil {
		t.Fatal(err)
	}
	needed, err := s.BeginSharedUpdates(before.Subscription, updates)
	if err != nil {
		t.Fatal(err)
	}
	if !needed {
		return
	}
	if err := s.db.First(&paused).Error; err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointAdvance(before, paused, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admission(before.Subscription, owner, 100); err != ErrFrozen {
		t.Fatalf("missing barrier: %v", err)
	}
	if _, _, err := s.CommitSharedUpdates(before.Subscription, owner, key); err != nil {
		t.Fatal(err)
	}
	if err := s.db.First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointAdvance(paused, after, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointAdvance(before, after, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSharedResetDoesNotWaitForOfflineNodeOrBillOldCycle(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	a, b := rollingStore(t, p, "a"), rollingStore(t, p, "b")
	if err := a.Observe(p.Subscription, "de", keys["de"], 250, 100); err != nil {
		t.Fatal(err)
	}
	if err := b.Observe(p.Subscription, "at", keys["at"], 300, 100); err != nil {
		t.Fatal(err)
	}
	oldB, _ := b.Load(p.Subscription)
	if err := a.Merge(p.Subscription, oldB.Snapshot()); err != nil {
		t.Fatal(err)
	}
	u, err := SignPolicyUpdate(p, "reset-1", "reset", 1000, 0, authority)
	if err != nil {
		t.Fatal(err)
	}
	applyRolling(t, a, "de", keys["de"], u)
	if err := a.Observe(p.Subscription, "de", keys["de"], 270, 100); err != nil {
		t.Fatal(err)
	}
	// Isolated B keeps serving its previous policy. Its late old-cycle bytes
	// remain auditable but cannot resurrect the reset subscription's cards.
	if err := b.Observe(p.Subscription, "at", keys["at"], 700, 100); err != nil {
		t.Fatal(err)
	}
	lateB, _ := b.Load(p.Subscription)
	for i := 0; i < 5; i++ {
		if err := a.Merge(p.Subscription, lateB.Snapshot()); err != nil {
			t.Fatal(err)
		}
		applyRolling(t, a, "de", keys["de"], u)
	}
	al, _ := a.Load(p.Subscription)
	assertBilled(t, al, 20)
	applyRolling(t, b, "at", keys["at"], u)
	if err := b.Observe(p.Subscription, "at", keys["at"], 730, 100); err != nil {
		t.Fatal(err)
	}
	bl, _ := b.Load(p.Subscription)
	if err := a.Merge(p.Subscription, bl.Snapshot()); err != nil {
		t.Fatal(err)
	}
	al, _ = a.Load(p.Subscription)
	assertBilled(t, al, 50)
	if al.rows["at"].Row.Used != 730 || al.rows["at"].Row.ResetAt != 700 {
		t.Fatal("lost lifetime audit")
	}
}

func TestSharedRenewalIncludesOfflineUsageExactlyOnce(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	p.AlreadyBilled = 50
	a, b := rollingStore(t, p, "a"), rollingStore(t, p, "b")
	if err := a.Observe(p.Subscription, "de", keys["de"], 150, 100); err != nil {
		t.Fatal(err)
	}
	if err := b.Observe(p.Subscription, "at", keys["at"], 600, 100); err != nil {
		t.Fatal(err)
	}
	u, err := SignPolicyUpdate(p, "renew-1", "renew", 2000, 5000, authority)
	if err != nil {
		t.Fatal(err)
	}
	applyRolling(t, a, "de", keys["de"], u)
	applyRolling(t, b, "at", keys["at"], u)
	bl, _ := b.Load(p.Subscription)
	for i := 0; i < 10; i++ {
		if err := a.Merge(p.Subscription, bl.Snapshot()); err != nil {
			t.Fatal(err)
		}
	}
	al, _ := a.Load(p.Subscription)
	assertBilled(t, al, 800)
	if available, err := al.Available("de", 100); err != nil || available != 1200 {
		t.Fatalf("remaining=%d err=%v", available, err)
	}
}

func TestSharedCatchupMultipleResetsAndRenewalsIsAtomicAndReplaySafe(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	s := rollingStore(t, p, "node")
	if err := s.Observe(p.Subscription, "de", keys["de"], 900, 100); err != nil {
		t.Fatal(err)
	}
	u1, _ := SignPolicyUpdate(p, "reset-1", "reset", 1000, 0, authority)
	u2, _ := SignPolicyUpdate(u1.Next, "renew-1", "renew", 2000, 0, authority)
	u3, _ := SignPolicyUpdate(u2.Next, "reset-2", "reset", 3000, 0, authority)
	applyRolling(t, s, "de", keys["de"], u1, u2, u3)
	if err := s.Observe(p.Subscription, "de", keys["de"], 950, 100); err != nil {
		t.Fatal(err)
	}
	applyRolling(t, s, "de", keys["de"], u1, u2, u3)
	l, _ := s.Load(p.Subscription)
	assertBilled(t, l, 50)
	fork, _ := SignPolicyUpdate(p, "other-reset", "reset", 1000, 0, authority)
	if _, err := s.BeginSharedUpdates(p.Subscription, []PolicyUpdate{fork}); err == nil {
		t.Fatal("signed old-version fork accepted")
	}
	if _, err := s.BeginSharedUpdates(p.Subscription, []PolicyUpdate{u3, u2}); err == nil {
		t.Fatal("reordered updates accepted")
	}
	bad := clone(u3)
	bad.Next.Limit++
	if VerifyPolicyUpdate(u2.Next, bad) == nil {
		t.Fatal("tampering accepted")
	}
}

func TestSharedRestoreAndFailedCommitCannotRemoveBarrierOrResetAgain(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	path := filepath.Join(t.TempDir(), "node.db")
	s, close := openStore(t, path)
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	u, _ := SignPolicyUpdate(p, "reset", "reset", 1000, 0, authority)
	if _, err := s.BeginSharedUpdates(p.Subscription, []PolicyUpdate{u}); err != nil {
		t.Fatal(err)
	}
	var paused Record
	if err := s.db.First(&paused).Error; err != nil {
		t.Fatal(err)
	}
	close()
	s, close = openStore(t, path)
	defer close()
	if _, err := s.Admission(p.Subscription, "de", 100); err != ErrFrozen {
		t.Fatal("restart lost barrier", err)
	}
	if err := s.db.Exec("CREATE TRIGGER reject_quota_update BEFORE UPDATE ON quota_escrow_states BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CommitSharedUpdates(p.Subscription, "de", keys["de"]); err == nil {
		t.Fatal("failed storage committed")
	}
	if err := s.db.Exec("DROP TRIGGER reject_quota_update").Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CommitSharedUpdates(p.Subscription, "de", keys["de"]); err != nil {
		t.Fatal(err)
	}
	var committed Record
	if err := s.db.First(&committed).Error; err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointAdvance(paused, committed, nil); err != nil {
		t.Fatal(err)
	}
	tampered := committed
	tampered.Revision++
	pp := u.Next
	pp.Limit++
	body, _ := json.Marshal(pp)
	tampered.PolicyJSON = string(body)
	if ValidateCheckpointAdvance(committed, tampered, nil) == nil {
		t.Fatal("unsigned policy overwrite accepted")
	}
	tampered = paused
	tampered.Revision = committed.Revision + 1
	if ValidateCheckpointAdvance(committed, tampered, nil) == nil {
		t.Fatal("older policy with higher DB revision accepted")
	}
}

func TestSharedUnlimitedAndDisabledPolicyStillMetersAndExpires(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	s := rollingStore(t, p, "availability")
	u, err := SignPolicyChange(p, "unlimited", "renew", ControlTarget{Limit: 0, Unlimited: true, ExpiresAt: 5000}, authority)
	if err != nil {
		t.Fatal(err)
	}
	applyRolling(t, s, "de", keys["de"], u)
	if err := s.Observe(p.Subscription, "de", keys["de"], 50000, 100); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Admission(p.Subscription, "de", 100); err != nil || n <= 0 {
		t.Fatal("unlimited denied", n, err)
	}
	if n, err := s.Admission(p.Subscription, "de", 5001); err != nil || n != 0 {
		t.Fatal("expiry bypassed", n, err)
	}
	disabled, err := SignPolicyChange(u.Next, "disable", "renew", ControlTarget{Unlimited: true, Disabled: true, ExpiresAt: 5000}, authority)
	if err != nil {
		t.Fatal(err)
	}
	applyRolling(t, s, "de", keys["de"], u, disabled)
	if n, err := s.Admission(p.Subscription, "de", 100); err != nil || n != 0 {
		t.Fatal("disabled policy admitted", n, err)
	}
	l, err := s.Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 50000)
}
