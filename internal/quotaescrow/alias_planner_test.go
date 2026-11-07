package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func aliasPlannerFixture(t *testing.T) (PlanBuilder, Policy, map[string]map[string]InspectedAlias) {
	t.Helper()
	b, rows := plannerFixture(t)
	p := Policy{Subscription: "parent", Epoch: "epoch", Mode: "shared", Limit: 1000, AlreadyBilled: 42,
		Version: 1, ResetGeneration: 1, Manager: "master", Keys: clone(b.Keys), ControlKeys: clone(b.Keys),
		ControlEpoch: "control", Authority: b.Authority.Public().(ed25519.PublicKey), Grants: map[string]int64{},
		Aliases: AliasCatalog{"master": {"existing-phone": {Fingerprint: strings.Repeat("cd", 32), Revision: 1}}}}
	for owner := range rows {
		p.Grants[owner] = 0
		a := rows[owner]["device-1"]
		a.Enabled = false
		rows[owner]["device-1"] = a
	}
	return b, p, rows
}

func TestDevicePlannerAttachAndOfflineRevokeWholeLogicalDevice(t *testing.T) {
	b, p, rows := aliasPlannerFixture(t)
	patches, err := b.AliasChanges(context.Background(), p, "master", "device-1", false)
	if err != nil || len(patches) != 3 {
		t.Fatal(patches, err)
	}
	u, err := DraftAliasChanges(p, "attach", patches)
	if err != nil || u.Next.AlreadyBilled != 42 {
		t.Fatal(u, err)
	}
	// Repeated discovery of the already attached topology is a no-op, and a
	// credential replacement may not impersonate the old logical device.
	for owner := range rows {
		a := rows[owner]["device-1"]
		a.Enabled, a.Subscription, a.Epoch = true, p.Subscription, p.Epoch
		rows[owner]["device-1"] = a
	}
	if _, err := b.AliasChanges(context.Background(), u.Next, "master", "device-1", false); err == nil {
		t.Fatal("repeated attach did not report no-op")
	}
	a := rows["node-a"]["device-1"]
	a.Claim.Fingerprint = strings.Repeat("ef", 32)
	rows["node-a"]["device-1"] = a
	if _, err := b.AliasChanges(context.Background(), u.Next, "master", "device-1", false); err == nil {
		t.Fatal("credential replacement was accepted as a harmless attach")
	}
	b.Inspect = func(context.Context, string, SignedInspection) (Inventory, error) {
		t.Fatal("offline revocation must use committed membership")
		return Inventory{}, errors.New("offline")
	}
	revocations, err := b.AliasChanges(context.Background(), u.Next, "master", "device-1", true)
	if err != nil || len(revocations) != 3 {
		t.Fatal(revocations, err)
	}
	for _, patch := range revocations {
		if !patch.Revoked || patch.ExpectedRevision != 1 || patch.Email != "device-1" {
			t.Fatal(patch)
		}
	}
	if !reflect.DeepEqual([]string{revocations[0].Owner, revocations[1].Owner, revocations[2].Owner}, []string{"master", "node-a", "node-b"}) {
		t.Fatal("unstable command order", revocations)
	}
}

func TestDevicePlannerRejectsUnsafeAttachment(t *testing.T) {
	for _, scenario := range []string{"enabled", "historical", "pending", "foreign-parent", "foreign-epoch", "cycle", "duplicate-path", "new-owner", "missing", "not-manager", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			b, p, rows := aliasPlannerFixture(t)
			a := rows["node-a"]["device-1"]
			owner, ctx := "master", context.Background()
			switch scenario {
			case "enabled":
				a.Enabled = true
			case "historical":
				a.LocalBilled = 1
			case "pending":
				a.Pending = true
			case "foreign-parent":
				a.Subscription = "other-parent"
			case "foreign-epoch":
				a.Epoch = "other-epoch"
			case "cycle":
				a.Children = []string{"master"}
			case "duplicate-path":
				a.Children = []string{"node-b"}
			case "new-owner":
				a.Children = []string{"unregistered"}
			case "missing":
				delete(rows["node-b"], "device-1")
			case "not-manager":
				owner = "node-a"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			rows["node-a"]["device-1"] = a
			if patches, err := b.AliasChanges(ctx, p, owner, "device-1", false); err == nil {
				t.Fatal("unsafe alias plan accepted", patches)
			}
		})
	}
}

func TestDevicePlannerIndependentRootsAndOfflineManagerRevocation(t *testing.T) {
	b, p, rows := aliasPlannerFixture(t)
	for owner := range rows {
		a := rows[owner]["device-1"]
		a.Children = nil
		rows[owner]["device-1"] = a
	}
	patches, err := b.AliasChangesForRoots(context.Background(), p, "master", "device-1", false, []string{"node-b", "master", "node-a"})
	if err != nil || len(patches) != 3 {
		t.Fatal(patches, err)
	}
	u, err := DraftAliasChanges(p, "attach", patches)
	if err != nil {
		t.Fatal(err)
	}
	b.Inspect = func(context.Context, string, SignedInspection) (Inventory, error) {
		t.Fatal("revocation must not need a live manager")
		return Inventory{}, errors.New("offline")
	}
	patches, err = b.AliasChanges(context.Background(), u.Next, "node-a", "device-1", true)
	if err != nil || len(patches) != 3 {
		t.Fatal(patches, err)
	}
	if _, err := b.AliasChanges(context.Background(), u.Next, "unknown", "device-1", true); err == nil {
		t.Fatal("unregistered controller admitted")
	}
}
