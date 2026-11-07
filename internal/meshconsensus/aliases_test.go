package meshconsensus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestAliasCommandsSurviveLaterRenewalsAndSnapshotWithoutReapplying(t *testing.T) {
	f, p, key := compactFixture(t)
	p.Aliases = quotaescrow.AliasCatalog{"a": {"phone": {Fingerprint: strings.Repeat("ab", 32), Revision: 1}}}
	r, _ := SignRegistration(p, key)
	applyCompact(t, f, Command{ID: "registration", Registration: &r})
	add := Command{ID: "tablet", Subscription: p.Subscription, Kind: "alias", Alias: &quotaescrow.AliasPatch{Owner: "a", Email: "tablet", Fingerprint: strings.Repeat("cd", 32)}}
	first := applyCompact(t, f, add)
	for i := 0; i < 400; i++ {
		applyCompact(t, f, Command{ID: fmt.Sprint("renew-", i), Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 1}})
	}
	revoke := Command{ID: "tablet-revoked", Subscription: p.Subscription, Kind: "alias", Alias: &quotaescrow.AliasPatch{Owner: "a", Email: "tablet", ExpectedRevision: 1, Fingerprint: strings.Repeat("cd", 32), Revoked: true}}
	applyCompact(t, f, revoke)
	latest, _ := f.Policy(p.Subscription)
	if latest.Limit != p.Limit+400 || latest.ResetGeneration != 1 || latest.Aliases["a"]["tablet"].Revision != 2 || !latest.Aliases["a"]["tablet"].Revoked {
		t.Fatal("incorrect membership/accounting")
	}
	if n := len(f.data.Subscriptions[p.Subscription].AliasSets); n != 3 {
		t.Fatalf("renewals duplicated alias history: %d", n)
	}
	restored, _ := NewFSM(p.ControlEpoch, p.ControlKeys, p.Authority)
	data := snapshotBytes(t, f)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(data))); err != nil {
		t.Fatal(err)
	}
	repeated := applyCompact(t, restored, add)
	if !quotaescrow.SamePolicyUpdate(*first.Update, *repeated.Update) {
		t.Fatal("lost immutable request result")
	}
	after, _ := restored.Policy(p.Subscription)
	if quotaescrow.PolicyHash(after) != quotaescrow.PolicyHash(latest) {
		t.Fatal("retry changed current quota or revived tablet")
	}
	bad := add
	bad.ID = "stale"
	bad.Alias = &quotaescrow.AliasPatch{Owner: "a", Email: "tablet", ExpectedRevision: 1, Fingerprint: strings.Repeat("cd", 32)}
	b, _ := json.Marshal(bad)
	if result := restored.Apply(&raft.Log{Data: b}).(Result); result.Error == "" {
		t.Fatal("stale alias revision accepted")
	}
	var tampered state
	if err := json.Unmarshal(data, &tampered); err != nil {
		t.Fatal(err)
	}
	// Remove a catalog referenced by an immutable receipt. The initial catalog
	// is also present in Base.Policy and need not have a separate cached copy.
	delete(tampered.Subscriptions[p.Subscription].AliasSets, tampered.Requests["tablet"].Value.AliasHash)
	b, _ = json.Marshal(tampered)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(b))); err == nil {
		t.Fatal("snapshot lost historical authorization without rejection")
	}
}

func TestDeviceBatchIsAtomicAndRejectsStalePartialRevocation(t *testing.T) {
	f, p, key := compactFixture(t)
	p.Aliases = quotaescrow.AliasCatalog{"a": {"phone": {Fingerprint: strings.Repeat("ab", 32), Revision: 1}}}
	r, _ := SignRegistration(p, key)
	applyCompact(t, f, Command{ID: "registration", Registration: &r})
	add := Command{ID: "attach-device", Subscription: p.Subscription, Kind: "alias", DeviceHash: quotaescrow.DeviceAuthorizationHash(p, "tablet"), AliasBatch: []quotaescrow.AliasPatch{
		{Owner: "a", Email: "tablet", Fingerprint: strings.Repeat("cd", 32)},
		{Owner: "b", Email: "tablet", Fingerprint: strings.Repeat("ef", 32)},
	}}
	first := applyCompact(t, f, add)
	if first.Update.Next.Version != 2 || len(first.Update.Next.Aliases["b"]) != 1 {
		t.Fatal("device group did not commit together")
	}
	old := first.Update.Next
	// A third serving member joins before a delayed two-member revoke arrives.
	join := Command{ID: "third-owner", Subscription: p.Subscription, Kind: "alias", DeviceHash: quotaescrow.DeviceAuthorizationHash(old, "tablet"), AliasBatch: []quotaescrow.AliasPatch{{Owner: "c", Email: "tablet", Fingerprint: strings.Repeat("11", 32)}}}
	applyCompact(t, f, join)
	revoke := Command{ID: "stale-revoke", Subscription: p.Subscription, Kind: "alias", DeviceHash: quotaescrow.DeviceAuthorizationHash(old, "tablet"), AliasBatch: []quotaescrow.AliasPatch{
		{Owner: "a", Email: "tablet", ExpectedRevision: 1, Fingerprint: strings.Repeat("cd", 32), Revoked: true},
		{Owner: "b", Email: "tablet", ExpectedRevision: 1, Fingerprint: strings.Repeat("ef", 32), Revoked: true},
	}}
	b, _ := json.Marshal(revoke)
	if out := f.Apply(&raft.Log{Data: b}).(Result); out.Error == "" {
		t.Fatal("stale revoke silently omitted a live owner")
	}
	latest, _ := f.Policy(p.Subscription)
	revoke.ID = "complete-revoke"
	revoke.DeviceHash = quotaescrow.DeviceAuthorizationHash(latest, "tablet")
	revoke.AliasBatch = append(revoke.AliasBatch, quotaescrow.AliasPatch{Owner: "c", Email: "tablet", ExpectedRevision: 1, Fingerprint: strings.Repeat("11", 32), Revoked: true})
	final := applyCompact(t, f, revoke)
	for _, owner := range []string{"a", "b", "c"} {
		if !final.Update.Next.Aliases[owner]["tablet"].Revoked {
			t.Fatal("incomplete group revocation")
		}
	}
	if err := quotaescrow.VerifyPolicyCheckpointShape(p, *final.Update); err != nil {
		t.Fatal("offline group catch-up failed", err)
	}
	if result := applyCompact(t, f, add); result.Update.Next.Version != 2 {
		t.Fatal("replayed attach created a new operation")
	}
	current, _ := f.Policy(p.Subscription)
	if quotaescrow.PolicyHash(current) != quotaescrow.PolicyHash(final.Update.Next) {
		t.Fatal("replay re-enabled revoked group")
	}
}
