package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func controlFixture(t *testing.T, owners ...string) (*MeshControl, ed25519.PrivateKey, quotaescrow.ControlPlan, *MeshCheckpoint) {
	t.Helper()
	setupConflictDB(t)
	db := database.GetDB()
	// Each member owns a separate connection pool: initializing the second
	// panel replaces the legacy global test DB and closes its previous pool.
	independent, openErr := gorm.Open(sqlite.Open(db.Dialector.(*sqlite.Dialector).DSN), &gorm.Config{Logger: db.Logger})
	if openErr != nil {
		t.Fatal(openErr)
	}
	db = independent
	sqlDB, openErr := db.DB()
	if openErr != nil {
		t.Fatal(openErr)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	owner := "local"
	if len(owners) == 1 {
		owner = owners[0]
	}
	if err := db.AutoMigrate(&model.MeshControlState{}); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, secret, _ := ed25519.GenerateKey(rand.Reader)
	client := model.ClientRecord{Email: "phone", SubID: "subscription", UUID: "credential", Enable: true}
	if err := db.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	inbound := model.Inbound{Tag: "one", Port: 12345, Protocol: "vless", Settings: `{"clients":[{"email":"phone","id":"credential"}]}`, Enable: true}
	if err := db.Create(&inbound).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.LocalUsage{Email: "phone", Source: "stable", Billed: 900}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{Email: "phone", Enable: true, Up: 50, Down: 50}).Error; err != nil {
		t.Fatal(err)
	}
	fingerprint, err := MeshAliasFingerprint(db, "phone")
	if err != nil {
		t.Fatal(err)
	}
	plan := quotaescrow.ControlPlan{ID: "enroll-one", Subscription: "master/subscription", Kind: "enroll", NextEpoch: "first", Claims: map[string][]quotaescrow.AliasClaim{owner: {{Email: "phone", Fingerprint: fingerprint}}}}
	cp, err := OpenMeshCheckpoint(db, &MeshConfig{Owner: owner, PrivateKey: key, StateDir: t.TempDir()}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	c := &MeshControl{DB: db, Owner: owner, Key: key, Authority: authority, Enforcer: &MeshEnforcer{DB: db, Fence: func(_ context.Context, emails []string) error {
		pending, err := meshPendingAliases(db)
		if err != nil {
			return err
		}
		if !pending["phone"] || len(emails) != 1 || emails[0] != "phone" {
			t.Fatal("fence preceded durable barrier", pending, emails)
		}
		return nil
	}}, Drain: func(context.Context, []string) error { return nil }, Flush: func(context.Context) error { return nil }, Checkpoint: func() error { return cp.Advance(db) }}
	return c, secret, plan, cp
}

func controlRequest(t *testing.T, c *MeshControl, authority ed25519.PrivateKey, plan quotaescrow.ControlPlan, operation string, policy *quotaescrow.Policy, receipts []quotaescrow.ControlReceipt) (quotaescrow.ControlReceipt, error) {
	t.Helper()
	now := time.Now().Unix()
	signed, err := quotaescrow.SignControl(quotaescrow.ControlCommand{Plan: plan, Operation: operation, Policy: policy, Receipts: receipts, IssuedAt: now - 1, ValidUntil: now + 60}, authority)
	if err != nil {
		return quotaescrow.ControlReceipt{}, err
	}
	return c.Execute(context.Background(), signed)
}

func TestMeshControlEnrollmentRenewResetAndIdempotency(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	trace := []string{}
	fence := c.Enforcer.Fence
	c.Enforcer.Fence = func(ctx context.Context, emails []string) error {
		trace = append(trace, "fence")
		return fence(ctx, emails)
	}
	c.Drain = func(context.Context, []string) error { trace = append(trace, "drain"); return nil }
	flushCount := 0
	c.Flush = func(context.Context) error {
		trace = append(trace, "flush")
		flushCount++
		if flushCount == 1 {
			return c.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 17, 0) })
		}
		return nil
	}
	receipt, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(trace, []string{"fence", "drain", "flush"}) || receipt.Local["phone"] != 917 {
		t.Fatal(trace, receipt)
	}
	replay, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil || !reflect.DeepEqual(receipt, replay) || flushCount != 1 {
		t.Fatal("prepare retry changed baseline", err)
	}
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, AlreadyBilled: 100, Grants: map[string]int64{"local": 900}, Keys: map[string][]byte{"local": c.Key.Public().(ed25519.PublicKey)}}
	if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{receipt}); err != nil {
		t.Fatal(err)
	}
	assertBilled := func(want int64) {
		t.Helper()
		ledger, err := quotaescrow.NewStore(c.DB).Load(plan.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ledger.Billed()
		if err != nil || got != want {
			t.Fatalf("billed %d want %d: %v", got, want, err)
		}
	}
	assertBilled(100)
	if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{receipt}); err != nil {
		t.Fatal(err)
	}
	if flushCount != 2 {
		t.Fatal("committed retry flushed again")
	}
	if err := c.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 30, 0) }); err != nil {
		t.Fatal(err)
	}
	failures, err := SettleMeshMeters(c.DB, func(string) (ed25519.PrivateKey, error) { return c.Key, nil })
	if err != nil || len(failures) != 0 {
		t.Fatal(failures, err)
	}
	assertBilled(130)
	for _, kind := range []string{"renew", "reset"} {
		plan.ID = kind
		plan.Kind = kind
		plan.Epoch = policy.Epoch
		plan.NextEpoch = kind + "-epoch"
		receipt, err = controlRequest(t, c, authority, plan, "prepare", nil, nil)
		if err != nil {
			t.Fatal(kind, err)
		}
		policy.Epoch = plan.NextEpoch
		policy.Limit = 2000
		policy.AlreadyBilled = 130
		if kind == "reset" {
			policy.AlreadyBilled = 0
		}
		policy.Grants["local"] = policy.Limit - policy.AlreadyBilled
		if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{receipt}); err != nil {
			t.Fatal(kind, err)
		}
		assertBilled(policy.AlreadyBilled)
		if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{receipt}); err != nil {
			t.Fatal(kind, err)
		}
		assertBilled(policy.AlreadyBilled)
	}
	if err := c.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 5, 6) }); err != nil {
		t.Fatal(err)
	}
	failures, err = SettleMeshMeters(c.DB, func(string) (ed25519.PrivateKey, error) { return c.Key, nil })
	if err != nil || len(failures) != 0 {
		t.Fatal(failures, err)
	}
	assertBilled(11)
}

func TestMeshControlDrainFailurePersistsBarrierAndDetectsRestore(t *testing.T) {
	c, authority, plan, cp := controlFixture(t)
	c.Drain = func(context.Context, []string) error { return errors.New("unfinished handler") }
	flushed := false
	c.Flush = func(context.Context) error { flushed = true; return nil }
	if _, err := controlRequest(t, c, authority, plan, "prepare", nil, nil); err == nil {
		t.Fatal("accepted unfinished handler")
	}
	if flushed {
		t.Fatal("sampled before drain")
	}
	blocked, err := MeshBlockedEmailsNow(c.DB)
	if err != nil || !blocked["phone"] {
		t.Fatal("restart barrier missing", blocked, err)
	}
	if allowed, err := MeshClientAllowed("phone"); err != nil || allowed {
		t.Fatal("hot admission bypassed pending barrier", err)
	}
	if err := c.DB.Delete(&model.MeshControlState{}, "id = ?", plan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := cp.Advance(c.DB); !errors.Is(err, ErrMeshRestore) {
		t.Fatal("restored pre-enrollment database accepted", err)
	}
}

func TestMeshControlRejectsWrongAuthorityCredentialAndLateBytes(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	_, intruder, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := controlRequest(t, c, intruder, plan, "prepare", nil, nil); err == nil {
		t.Fatal("peer enrolled another user")
	}
	claims := plan.Claims["local"]
	saved := claims[0].Fingerprint
	claims[0].Fingerprint = string(make([]byte, 64))
	if _, err := controlRequest(t, c, authority, plan, "prepare", nil, nil); err == nil {
		t.Fatal("unbound alias accepted")
	}
	claims[0].Fingerprint = saved
	var n int64
	c.DB.Model(&model.MeshControlState{}).Count(&n)
	if n != 0 {
		t.Fatal("unauthorized request modified DB")
	}
	receipt, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, Grants: map[string]int64{"local": 1000}, Keys: map[string][]byte{"local": c.Key.Public().(ed25519.PublicKey)}}
	if err := c.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 1, 0) }); err != nil {
		t.Fatal(err)
	}
	if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{receipt}); err == nil {
		t.Fatal("late byte disappeared in new baseline")
	}
	var bindings int64
	c.DB.Model(&model.MeshBinding{}).Count(&bindings)
	if bindings != 0 {
		t.Fatal("failed enrollment partly committed")
	}
}
