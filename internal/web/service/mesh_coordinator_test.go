package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func TestMeshCoordinatorRestartAndLostCommitReplyDoNotResetAgain(t *testing.T) {
	a, authority, plan, _ := controlFixture(t, "a")
	b, _, other, _ := controlFixture(t, "b")
	b.Authority = a.Authority
	plan.Claims["b"] = other.Claims["b"]
	if err := a.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]*MeshControl{"a": a, "b": b}
	keys := map[string][]byte{"a": a.Key.Public().(ed25519.PublicKey), "b": b.Key.Public().(ed25519.PublicKey)}
	calls := map[string]int{}
	failPrepare := true
	loseCommit := false
	call := func(ctx context.Context, owner string, signed quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		calls[owner+"/"+signed.Command.Operation]++
		if owner == "b" && signed.Command.Operation == "prepare" && failPrepare {
			failPrepare = false
			return quotaescrow.ControlReceipt{}, errors.New("peer unreachable")
		}
		r, err := nodes[owner].Execute(ctx, signed)
		if err == nil && owner == "b" && signed.Command.Operation == "commit" && loseCommit {
			loseCommit = false
			return quotaescrow.ControlReceipt{}, errors.New("reply lost after commit")
		}
		return r, err
	}
	baselineCalls := 0
	initial := func(context.Context, quotaescrow.ControlPlan, []quotaescrow.ControlReceipt) (int64, error) {
		baselineCalls++
		return 100, nil
	}
	coordinator := &quotaescrow.Coordinator{DB: a.DB, Authority: authority, Call: call, InitialUsage: initial}
	target := quotaescrow.ControlTarget{Limit: 1000, Weights: map[string]int64{"a": 8, "b": 1}}
	if err := coordinator.Create(plan, nil, target, keys); err != nil {
		t.Fatal(err)
	}
	if _, done, err := coordinator.Resume(context.Background(), plan.ID); err == nil || done {
		t.Fatal("completed with missing prepare")
	}
	if baselineCalls != 0 || calls["a/prepare"] != 1 {
		t.Fatal("cutover before all nodes were fenced")
	}
	// New coordinator instance has no in-memory receipt state.
	coordinator = &quotaescrow.Coordinator{DB: a.DB, Authority: authority, Call: call, InitialUsage: initial}
	policy, done, err := coordinator.Resume(context.Background(), plan.ID)
	if err != nil || !done {
		t.Fatal(err)
	}
	if calls["a/prepare"] != 1 || baselineCalls != 1 || policy.AlreadyBilled != 100 || policy.Grants["a"]+policy.Grants["b"] != 900 {
		t.Fatal("resumed enrollment rebilled or reallocated", calls, baselineCalls, policy)
	}
	plan.ID = "lost-reset-reply"
	plan.Kind = "reset"
	plan.Epoch = policy.Epoch
	plan.NextEpoch = "reset-next"
	target.Limit = 1500
	if err := coordinator.Create(plan, &policy, target, keys); err != nil {
		t.Fatal(err)
	}
	loseCommit = true
	if _, done, err := coordinator.Resume(context.Background(), plan.ID); err == nil || done {
		t.Fatal("lost response reported complete")
	}
	// The member was already allowed to use its new epoch before the master
	// recovered the acknowledgement. Retrying must retain these nine bytes.
	if err := b.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 9, 0) }); err != nil {
		t.Fatal(err)
	}
	failures, err := SettleMeshMeters(b.DB, func(string) (ed25519.PrivateKey, error) { return b.Key, nil })
	if err != nil || len(failures) != 0 {
		t.Fatal(failures, err)
	}
	coordinator = &quotaescrow.Coordinator{DB: a.DB, Authority: authority, Call: call, InitialUsage: initial}
	_, done, err = coordinator.Resume(context.Background(), plan.ID)
	if err != nil || !done {
		t.Fatal(err)
	}
	ledger, err := quotaescrow.NewStore(b.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	used, err := ledger.Billed()
	if err != nil || used != 9 {
		t.Fatal("recovery reset new epoch consumption", used, err)
	}
	if baselineCalls != 1 {
		t.Fatal("reset recomputed historical baseline")
	}
	before := calls["b/commit"]
	_, done, err = coordinator.Resume(context.Background(), plan.ID)
	if err != nil || !done || calls["b/commit"] != before {
		t.Fatal("completed operation resent commands", err)
	}
}

func TestMeshCoordinatorEnrollsControlOnlyMasterFromSignedHistory(t *testing.T) {
	a, authority, plan, _ := controlFixture(t, "master")
	b, _, other, _ := controlFixture(t, "child")
	b.Authority = a.Authority
	if err := a.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.Create(&model.Node{Id: 1, Name: "child", Guid: "child", Address: "127.0.0.1", Port: 45601}).Error; err != nil {
		t.Fatal(err)
	}
	if err := a.DB.Model(&model.Inbound{}).Where("tag = ?", "one").Update("node_id", 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := a.DB.Model(&xray.ClientTraffic{}).Where("email = ?", "phone").Updates(map[string]any{"up": 0, "down": 100}).Error; err != nil {
		t.Fatal(err)
	}
	if err := b.DB.Model(&xray.ClientTraffic{}).Where("email = ?", "phone").Updates(map[string]any{"up": 0, "down": 65}).Error; err != nil {
		t.Fatal(err)
	}
	if err := a.DB.Create(&model.NodeClientTraffic{NodeId: 1, Email: "phone", Down: 60}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	inspection, err := quotaescrow.SignInspection(quotaescrow.Inspection{Owner: a.Owner, Nonce: "control-only-inspection", Emails: []string{"phone"}, IssuedAt: now - 1, ValidUntil: now + 60}, authority)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := a.Inspect(inspection)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Aliases[0].Local || len(inventory.Aliases[0].Children) != 1 || inventory.Aliases[0].Children[0] != "child" {
		t.Fatal("control-only inventory not recognized", inventory)
	}
	plan.Claims["master"] = []quotaescrow.AliasClaim{inventory.Aliases[0].Claim}
	plan.Claims["child"] = other.Claims["child"]
	plan.AccountingRoots = []quotaescrow.LegacyRoot{{Owner: "master", Alias: "phone"}}
	keys := map[string][]byte{"master": a.Key.Public().(ed25519.PublicKey), "child": b.Key.Public().(ed25519.PublicKey)}
	c := &quotaescrow.Coordinator{DB: a.DB, Authority: authority, Call: func(ctx context.Context, owner string, command quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		if owner == "master" {
			return a.Execute(ctx, command)
		}
		return b.Execute(ctx, command)
	}}
	if err := c.Create(plan, nil, quotaescrow.ControlTarget{Limit: 1000, Weights: map[string]int64{"master": 0}}, keys); err != nil {
		t.Fatal(err)
	}
	policy, done, err := c.Resume(context.Background(), plan.ID)
	if err != nil || !done {
		t.Fatal(done, err)
	}
	if policy.AlreadyBilled != 105 || policy.Grants["master"] != 0 || policy.Grants["child"] != 895 {
		t.Fatal("control-only master lost usage or reserved credit", policy)
	}
}

func TestMeshCoordinatorCannotInventHistoricalUsage(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	if err := c.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	coordinator := &quotaescrow.Coordinator{DB: c.DB, Authority: authority, Call: func(ctx context.Context, _ string, signed quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		return c.Execute(ctx, signed)
	}}
	if err := coordinator.Create(plan, nil, quotaescrow.ControlTarget{Limit: 1000}, map[string][]byte{"local": c.Key.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatal(err)
	}
	if _, done, err := coordinator.Resume(context.Background(), plan.ID); err == nil || done {
		t.Fatal("guessed historical usage")
	}
	blocked, err := meshPendingAliases(c.DB)
	if err != nil || !blocked["phone"] {
		t.Fatal("missing baseline reopened user", err)
	}
}
