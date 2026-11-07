//go:build cgo

package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

func checkpointFixture(t *testing.T) (Policy, map[string]ed25519.PrivateKey) {
	p, keys, _ := rollingFixture(t)
	p.ControlEpoch, p.ControlKeys = "majority-checkpoint", clone(p.Keys)
	return p, keys
}

func checkpointUpdate(t *testing.T, p Policy, keys map[string]ed25519.PrivateKey, kind string, limit int64) PolicyUpdate {
	t.Helper()
	u, err := DraftPolicyChange(p, fmt.Sprintf("update-%d", p.Version+1), kind, ControlTarget{Limit: limit, ExpiresAt: p.ExpiresAt, Disabled: p.Disabled, Unlimited: p.Unlimited})
	if err != nil {
		t.Fatal(err)
	}
	u.Votes = map[string][]byte{}
	for _, id := range []string{"at", "de"} {
		u.Votes[id] = PolicyUpdateVote(u, keys[id])
	}
	return u
}

func TestMajorityCheckpointRejoinsAfterLongHistoryWithoutRebilling(t *testing.T) {
	initial, keys := checkpointFixture(t)
	initial.AlreadyBilled = 50
	current := initial
	var first, latest PolicyUpdate
	oldWireSize := 0
	for i := 0; i < 1600; i++ {
		kind := "renew"
		if i%5 == 0 {
			kind = "reset"
		}
		latest = checkpointUpdate(t, current, keys, kind, 10000+int64(i))
		if i == 0 {
			first = latest
		}
		b, _ := json.Marshal(latest)
		oldWireSize += len(b)
		current = latest.Next
	}
	if oldWireSize < maxExchangeBytes {
		t.Fatal("test did not exceed the previous wire limit", oldWireSize)
	}
	old := rollingStore(t, initial, "offline")
	active := rollingStore(t, initial, "online")
	if err := old.Observe(initial.Subscription, "nl", keys["nl"], 400, 100); err != nil {
		t.Fatal(err)
	}
	applyRolling(t, active, "at", keys["at"], latest)
	if err := active.Observe(initial.Subscription, "at", keys["at"], 17, 100); err != nil {
		t.Fatal(err)
	}
	apply := func(_ context.Context, sub string, updates []PolicyUpdate) error {
		needed, err := old.BeginSharedUpdates(sub, updates)
		if err != nil || !needed {
			return err
		}
		_, _, err = old.CommitSharedUpdates(sub, "nl", keys["nl"])
		return err
	}
	server := httptest.NewTLSServer(HTTPExchange{Store: old, Owner: "nl", Key: keys["nl"], ApplyUpdates: apply}.Handler())
	defer server.Close()
	exchange := HTTPExchange{Store: active, Owner: "at", Key: keys["at"], Subscription: initial.Subscription, Peers: map[string]string{"nl": server.URL}, Client: server.Client(), ApplyUpdates: func(_ context.Context, sub string, updates []PolicyUpdate) error {
		needed, err := active.NeedsSharedUpdates(sub, updates)
		if needed {
			t.Error("current source should not need any policy replay")
		}
		return err
	}}
	l, _ := active.Load(initial.Subscription)
	for i := 0; i < 3; i++ {
		if err := exchange.Attempt(context.Background(), "nl", "nl", l.Snapshot()); err != nil {
			t.Fatal("bounded checkpoint exchange failed", err)
		}
	}
	l, err := old.Load(initial.Subscription)
	if err != nil || l.policy.Version != current.Version || l.policy.ResetGeneration != current.ResetGeneration {
		t.Fatal("offline policy did not catch up", err)
	}
	assertBilled(t, l, 17)
	if err := old.Observe(initial.Subscription, "nl", keys["nl"], 423, 100); err != nil {
		t.Fatal(err)
	}
	// Old and current certificates cannot reset traffic recorded after catch-up.
	applyRolling(t, old, "nl", keys["nl"], first)
	applyRolling(t, old, "nl", keys["nl"], latest)
	l, _ = old.Load(initial.Subscription)
	assertBilled(t, l, 40)
	var stored Record
	if err := old.db.First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	proofs, _ := decodeUpdates(stored.UpdatesJSON)
	if len(proofs) != 1 || len(stored.UpdatesJSON) > 10000 {
		t.Fatal("history was not compacted", len(proofs), len(stored.UpdatesJSON))
	}
}

func TestMajorityCheckpointCannotChangeIdentityOrForgeReset(t *testing.T) {
	p, keys := checkpointFixture(t)
	first := checkpointUpdate(t, p, keys, "renew", 2000)
	latest := checkpointUpdate(t, first.Next, keys, "renew", 3000)
	if err := VerifyPolicyUpdate(p, latest); err != nil {
		t.Fatal("valid majority jump rejected", err)
	}
	for _, mutate := range []func(*PolicyUpdate){
		func(u *PolicyUpdate) { delete(u.Votes, "de") },
		func(u *PolicyUpdate) { u.Next.Epoch = "another-lifetime" },
		func(u *PolicyUpdate) { u.Next.Manager = "nl" },
		func(u *PolicyUpdate) { u.Next.ResetGeneration = p.ResetGeneration + 3 },
		func(u *PolicyUpdate) { u.Next.AlreadyBilled++ },
		func(u *PolicyUpdate) { u.Next.Limit++ },
	} {
		bad := clone(latest)
		mutate(&bad)
		if err := VerifyPolicyUpdate(p, bad); err == nil {
			t.Fatal("invalid checkpoint accepted")
		}
	}
	// Even legitimately signed incompatible membership cannot pass a checkpoint.
	bad := clone(latest)
	bad.Next.Epoch = "another-lifetime"
	for id := range bad.Votes {
		bad.Votes[id] = PolicyUpdateVote(bad, keys[id])
	}
	if err := VerifyPolicyUpdate(p, bad); err == nil {
		t.Fatal("checkpoint silently replaced the lifetime epoch")
	}
	legacy, _, authority := rollingFixture(t)
	a, _ := SignPolicyUpdate(legacy, "one", "renew", 2000, 0, authority)
	b, _ := SignPolicyUpdate(a.Next, "two", "renew", 3000, 0, authority)
	if err := VerifyPolicyUpdate(legacy, b); err == nil {
		t.Fatal("authority-only policy skipped its chain")
	}
}

func TestMajorityCheckpointKeepsUnappliedBarrierAndCounterFloor(t *testing.T) {
	p, keys := checkpointFixture(t)
	s := rollingStore(t, p, "barrier")
	a := checkpointUpdate(t, p, keys, "reset", 1000)
	b := checkpointUpdate(t, a.Next, keys, "renew", 2000)
	if err := s.Observe(p.Subscription, "at", keys["at"], 50, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginSharedUpdates(p.Subscription, []PolicyUpdate{b}); err != nil {
		t.Fatal(err)
	}
	var paused Record
	s.db.First(&paused)
	broken := paused
	broken.Revision++
	broken.PendingUpdatesJSON, broken.PausedFor, broken.PausedEpoch = "[]", "", ""
	if err := ValidateCheckpointAdvance(paused, broken, nil); err == nil {
		t.Fatal("pending checkpoint disappeared without commit")
	}
	applyRolling(t, s, "at", keys["at"], b)
	var committed Record
	s.db.First(&committed)
	broken = committed
	broken.Revision++
	broken.RowsJSON = "[]"
	if err := ValidateCheckpointAdvance(committed, broken, nil); err == nil {
		t.Fatal("compaction lost the signed lifetime usage floor")
	}
}
