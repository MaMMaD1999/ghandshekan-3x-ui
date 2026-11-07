package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func TestMeshSharedLifecycleOfflineResetRenewLostReplyAndRestart(t *testing.T) {
	a, authority, plan, _ := controlFixture(t, "a")
	b, _, other, _ := controlFixture(t, "b")
	b.Authority = a.Authority
	plan.Claims["b"] = other.Claims["b"]
	if err := a.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]*MeshControl{"a": a, "b": b}
	keys := map[string][]byte{"a": a.Key.Public().(ed25519.PublicKey), "b": b.Key.Public().(ed25519.PublicKey)}
	offline, loseReply := false, false
	updates := func(ctx context.Context, owner string, request quotaescrow.PolicyUpdateRequest) (quotaescrow.PolicyReceipt, error) {
		if owner == "a" && offline {
			return quotaescrow.PolicyReceipt{}, errors.New("master offline")
		}
		node := nodes[owner]
		if err := node.ApplySharedUpdates(ctx, request.Subscription, request.Updates); err != nil {
			return quotaescrow.PolicyReceipt{}, err
		}
		var record quotaescrow.Record
		if err := node.DB.First(&record).Error; err != nil {
			return quotaescrow.PolicyReceipt{}, err
		}
		var p quotaescrow.Policy
		if err := json.Unmarshal([]byte(record.PolicyJSON), &p); err != nil {
			return quotaescrow.PolicyReceipt{}, err
		}
		if owner == "b" && loseReply {
			loseReply = false
			return quotaescrow.PolicyReceipt{}, errors.New("committed reply lost")
		}
		return quotaescrow.SignPolicyReceipt(p, owner, node.Key)
	}
	call := func(ctx context.Context, owner string, s quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		return nodes[owner].Execute(ctx, s)
	}
	c := &quotaescrow.Coordinator{Owner: "a", DB: a.DB, Authority: authority, Call: call, UpdatePolicy: updates, InitialUsage: func(context.Context, quotaescrow.ControlPlan, []quotaescrow.ControlReceipt) (int64, error) {
		return 100, nil
	}}
	target := quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: 1000}
	if err := c.Create(plan, nil, target, keys); err != nil {
		t.Fatal(err)
	}
	policy, done, err := c.Resume(context.Background(), plan.ID)
	if err != nil || !done || policy.Version != 1 {
		t.Fatal("enrollment", policy.Version, done, err)
	}
	if err := b.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 30, 0) }); err != nil {
		t.Fatal(err)
	}
	builder := quotaescrow.PlanBuilder{Authority: authority, Keys: keys, Inspect: func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		t.Fatal("lifecycle tried to inspect offline membership")
		return quotaescrow.Inventory{}, nil
	}}
	renew, err := builder.Transition(context.Background(), "renew", plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	target.Limit = 2000
	if err := c.Create(renew, &policy, target, keys); err != nil {
		t.Fatal(err)
	}
	offline = true
	renewed, done, err := c.Resume(context.Background(), renew.ID)
	if done || err == nil {
		t.Fatal("offline ack incorrectly complete")
	}
	var traffic xray.ClientTraffic
	if err := b.DB.First(&traffic, "email = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	if traffic.Total != 2000 || traffic.Up+traffic.Down != 100 {
		t.Fatal("reachable node renewal cleared old cards/counters or was blocked", traffic)
	}
	bl, err := quotaescrow.NewStore(b.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := bl.Billed(); used != 130 {
		t.Fatal("renewal lost consumption", used)
	}
	reset, err := builder.Transition(context.Background(), "reset", renew, renewed)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(reset, &renewed, target, keys); err != nil {
		t.Fatal(err)
	}
	loseReply = true
	resetPolicy, done, err := c.Resume(context.Background(), reset.ID)
	if done || err == nil {
		t.Fatal("lost commit reply incorrectly complete")
	}
	if err := b.DB.First(&traffic, "email = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	if traffic.Up != 0 || traffic.Down != 0 {
		t.Fatal("reset retained old displayed consumption")
	}
	if err := b.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 9, 0) }); err != nil {
		t.Fatal(err)
	}
	// Coordinator restart, while an older renewal is still pending. Resuming
	// that older operation must deliver the full newer chain, not reopen epoch 2.
	c = &quotaescrow.Coordinator{Owner: "a", DB: a.DB, Authority: authority, Call: call, UpdatePolicy: updates}
	offline = false
	if _, done, err := c.Resume(context.Background(), renew.ID); err != nil || !done {
		t.Fatal("older recovery", done, err)
	}
	if _, done, err := c.Resume(context.Background(), reset.ID); err != nil || !done {
		t.Fatal("newer recovery", done, err)
	}
	failures, err := SettleMeshMeters(b.DB, func(string) (ed25519.PrivateKey, error) { return b.Key, nil })
	if err != nil || len(failures) > 0 {
		t.Fatal(err, failures)
	}
	bl, err = quotaescrow.NewStore(b.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := bl.Billed(); used != 9 {
		t.Fatal("replayed reset cleared new consumption", used)
	}
	var current quotaescrow.Record
	if err := a.DB.First(&current).Error; err != nil {
		t.Fatal(err)
	}
	var caughtUp quotaescrow.Policy
	if err := json.Unmarshal([]byte(current.PolicyJSON), &caughtUp); err != nil {
		t.Fatal(err)
	}
	if quotaescrow.PolicyHash(caughtUp) != quotaescrow.PolicyHash(resetPolicy) {
		t.Fatal("offline member stopped at obsolete renewal")
	}
	// Local accounting remains monotonic, even though display cards reset.
	var local model.LocalUsage
	if err := b.DB.First(&local, "email = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	if local.Billed != 939 {
		t.Fatal("reset damaged lifetime meter", local.Billed)
	}
}

func TestMeshSharedDrainFailureRetainsBarrierAndRecoversWithoutMaster(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	receipt, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Mode: "shared", Version: 1, ResetGeneration: 1, Manager: "local", Authority: c.Authority, Limit: 1000, Grants: map[string]int64{"local": 0}, Keys: map[string][]byte{"local": c.Key.Public().(ed25519.PublicKey)}}
	if _, err := controlRequest(t, c, authority, plan, "commit", &p, []quotaescrow.ControlReceipt{receipt}); err != nil {
		t.Fatal(err)
	}
	u, err := quotaescrow.SignPolicyUpdate(p, "offline-reset", "reset", 1000, 0, authority)
	if err != nil {
		t.Fatal(err)
	}
	c.Drain = func(context.Context, []string) error { return errors.New("core not responding") }
	if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{u}); err == nil {
		t.Fatal("undrained reset committed")
	}
	if _, err := quotaescrow.NewStore(c.DB).Admission(p.Subscription, "local", 100); err != quotaescrow.ErrFrozen {
		t.Fatal("barrier missing", err)
	}
	c.Drain = func(context.Context, []string) error { return nil }
	if err := c.ResumeSharedUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if available, err := quotaescrow.NewStore(c.DB).Admission(p.Subscription, "local", 100); err != nil || available != 1000 {
		t.Fatal("local recovery failed", available, err)
	}
	scope, err := meshReportScopes(c.DB)
	if err != nil || scope["phone"].Epoch != p.Epoch+"/cycle/2" {
		t.Fatal("old card scope survived", scope, err)
	}
}
