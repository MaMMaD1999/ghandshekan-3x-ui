package meshconsensus

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func compactFixture(t *testing.T) (*FSM, quotaescrow.Policy, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(nil)
	keys := map[string][]byte{}
	for _, id := range []string{"a", "b", "c"} {
		peer, _, _ := ed25519.GenerateKey(nil)
		keys[id] = peer
	}
	p := quotaescrow.Policy{Subscription: "long-lived", Epoch: "life", Mode: "shared", Limit: 100000, Version: 1, ResetGeneration: 1, Authority: pub, Manager: "a", Keys: keys, Grants: map[string]int64{"a": 0, "b": 0, "c": 0}, ControlEpoch: "cluster", ControlKeys: keys, ResetSchedule: &quotaescrow.ResetSchedule{Zone: "UTC", StartedAt: 1, Hourly: true}}
	f, err := NewFSM(p.ControlEpoch, keys, pub)
	if err != nil {
		t.Fatal(err)
	}
	return f, p, key
}

func applyCompact(t *testing.T, f *FSM, c Command) Result {
	t.Helper()
	b, _ := json.Marshal(c)
	out := f.Apply(&raft.Log{Data: b}).(Result)
	if out.Error != "" {
		t.Fatal(out.Error)
	}
	return out
}

func snapshotBytes(t *testing.T, f *FSM) []byte {
	t.Helper()
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s.(snapshot))
}

func TestTimerHistoryStaysBoundedAndManualRetriesSurviveCompaction(t *testing.T) {
	f, base, authority := compactFixture(t)
	r, _ := SignRegistration(base, authority)
	applyCompact(t, f, Command{ID: "registration", Registration: &r})
	manual := Command{ID: "manual-add", Subscription: base.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 123}}
	first := applyCompact(t, f, manual)
	var initialSize int
	for i := int64(1); i <= 2000; i++ {
		at := i * 3600
		applyCompact(t, f, Command{ID: ScheduledOperationID(base.Subscription, at), Subscription: base.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: at}})
		if i == 100 {
			initialSize = len(snapshotBytes(t, f))
		}
	}
	before, _ := f.Policy(base.Subscription)
	if before.Version != 2002 || before.ResetGeneration != 2001 || before.Limit != base.Limit+123 {
		t.Fatal("lost scheduled reset or quota edit")
	}
	if len(f.data.Requests) != 2 || len(f.data.Subscriptions[base.Subscription].Updates) != 2 {
		t.Fatal("timer history grows without bound")
	}
	data := snapshotBytes(t, f)
	if len(data) > initialSize+128 || len(data) > 20000 {
		t.Fatal("snapshot grows with elapsed timer history", initialSize, len(data))
	}
	// Use the same pinned identity, as a real restart does.
	restored, err := NewFSM(base.ControlEpoch, base.ControlKeys, base.Authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(io.NopCloser(bytes.NewReader(data))); err != nil {
		t.Fatal("restore compact state", err)
	}
	replay := applyCompact(t, restored, manual)
	if !quotaescrow.SamePolicyUpdate(*replay.Update, *first.Update) {
		t.Fatal("manual retry lost its exact original result")
	}
	latest, _ := restored.Policy(base.Subscription)
	if quotaescrow.PolicyHash(before) != quotaescrow.PolicyHash(latest) {
		t.Fatal("historical manual retry changed current quota")
	}
	for _, rejected := range []Command{
		{ID: ScheduledOperationID(base.Subscription, 3600), Subscription: base.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: 3600}},
		{ID: ScheduledOperationID(base.Subscription, 3600), Subscription: base.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 100}},
		{ID: "manual-add", Subscription: base.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 124}},
	} {
		b, _ := json.Marshal(rejected)
		if out := restored.Apply(&raft.Log{Data: b}).(Result); out.Error == "" {
			t.Fatal("stale or repurposed operation was admitted")
		}
	}
	after, _ := restored.Policy(base.Subscription)
	if quotaescrow.PolicyHash(before) != quotaescrow.PolicyHash(after) {
		t.Fatal("rejected operation changed policy")
	}
}

func TestCompactManualReceiptCannotChangeImmutableMembership(t *testing.T) {
	f, base, authority := compactFixture(t)
	r, _ := SignRegistration(base, authority)
	applyCompact(t, f, Command{ID: "registration", Registration: &r})
	applyCompact(t, f, Command{ID: "edit", Subscription: base.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 20}})
	data := snapshotBytes(t, f)
	var corrupted state
	json.Unmarshal(data, &corrupted)
	request := corrupted.Requests["edit"]
	request.Value.Generation = 5
	corrupted.Requests["edit"] = request
	bad, _ := json.Marshal(corrupted)
	if err := f.Restore(io.NopCloser(bytes.NewReader(bad))); err == nil {
		t.Fatal("impossible reset generation restored")
	}
	if err := f.Restore(io.NopCloser(bytes.NewReader(data))); err != nil {
		t.Fatal("valid state damaged by failed restore", err)
	}
}
