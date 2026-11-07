package service

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func TestMeshAdminQueueIdempotencyKeepsNewConsumption(t *testing.T) {
	node, authority, plan, _ := controlFixture(t, "manager")
	if err := node.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{"manager": node.Key.Public().(ed25519.PublicKey)}
	c := &quotaescrow.Coordinator{Owner: "manager", DB: node.DB, Authority: authority, Call: func(ctx context.Context, _ string, s quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		return node.Execute(ctx, s)
	}, InitialUsage: func(context.Context, quotaescrow.ControlPlan, []quotaescrow.ControlReceipt) (int64, error) {
		return 100, nil
	}}
	if err := c.Create(plan, nil, quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: 1000}, keys); err != nil {
		t.Fatal(err)
	}
	if _, done, err := c.Resume(context.Background(), plan.ID); err != nil || !done {
		t.Fatal(done, err)
	}
	admin := &MeshAdministrator{Coordinator: c, Local: node, wake: make(chan struct{}, 1)}
	first, err := admin.Queue(context.Background(), plan.Subscription, "reset", "same-request", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 17, 0) }); err != nil {
		t.Fatal(err)
	}
	repeated, err := admin.Queue(context.Background(), plan.Subscription, "reset", "same-request", nil, nil)
	if err != nil || first.Operation != repeated.Operation {
		t.Fatal("retry changed operation", err)
	}
	failures, err := SettleMeshMeters(node.DB, func(string) (ed25519.PrivateKey, error) { return node.Key, nil })
	if err != nil || len(failures) > 0 {
		t.Fatal(failures, err)
	}
	l, err := quotaescrow.NewStore(node.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := l.Billed(); used != 17 {
		t.Fatal("repeat reset cleared new bytes", used)
	}
	limit := int64(2000)
	if _, err := admin.Queue(context.Background(), plan.Subscription, "reset", "same-request", &limit, nil); err == nil {
		t.Fatal("changed retry inputs accepted")
	}
	// A new renewal is allowed while remote acknowledgements of the reset are
	// pending; it must not accidentally clear the new cycle's usage.
	if _, err := admin.Queue(context.Background(), plan.Subscription, "renew", "next-request", &limit, nil); err != nil {
		t.Fatal(err)
	}
	l, err = quotaescrow.NewStore(node.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := l.Billed(); used != 17 {
		t.Fatal("renewal cleared usage", used)
	}
}
