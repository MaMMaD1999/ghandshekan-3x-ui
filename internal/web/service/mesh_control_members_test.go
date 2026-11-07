package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func TestMeshControlTwoMembersCannotRenewAroundMissingProof(t *testing.T) {
	a, authority, plan, _ := controlFixture(t, "a")
	b, _, other, _ := controlFixture(t, "b")
	b.Authority = a.Authority
	plan.Claims["b"] = other.Claims["b"]
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, AlreadyBilled: 100, Grants: map[string]int64{"a": 450, "b": 450}, Keys: map[string][]byte{"a": a.Key.Public().(ed25519.PublicKey), "b": b.Key.Public().(ed25519.PublicKey)}}
	prepared := make([]quotaescrow.ControlReceipt, 0, 2)
	for _, node := range []*MeshControl{a, b} {
		r, err := controlRequest(t, node, authority, plan, "prepare", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared = append(prepared, r)
	}
	for _, node := range []*MeshControl{a, b} {
		if _, err := controlRequest(t, node, authority, plan, "commit", &policy, prepared); err != nil {
			t.Fatal(err)
		}
		if _, err := controlRequest(t, node, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{prepared[1], prepared[0]}); err != nil {
			t.Fatal("receipt order changed idempotency", err)
		}
	}
	for i, node := range []*MeshControl{a, b} {
		used := []int64{120, 80}[i]
		if err := node.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", used, 0) }); err != nil {
			t.Fatal(err)
		}
		failures, err := SettleMeshMeters(node.DB, func(string) (ed25519.PrivateKey, error) { return node.Key, nil })
		if err != nil || len(failures) > 0 {
			t.Fatal(failures, err)
		}
	}
	plan.ID = "renew-both"
	plan.Kind = "renew"
	plan.Epoch = policy.Epoch
	plan.NextEpoch = "renewed"
	ra, err := controlRequest(t, a, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.Drain = func(context.Context, []string) error { return errors.New("link/handler unavailable") }
	if _, err := controlRequest(t, b, authority, plan, "prepare", nil, nil); err == nil {
		t.Fatal("accepted failed remote drain")
	}
	policy.Epoch = plan.NextEpoch
	policy.Limit = 1200
	policy.AlreadyBilled = 300
	if _, err := controlRequest(t, a, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{ra}); err == nil {
		t.Fatal("reissued old remote rights without final proof")
	}
	for _, node := range []*MeshControl{a, b} {
		if n, err := quotaescrow.NewStore(node.DB).Admission(plan.Subscription, node.Owner, 1); err == nil || n != 0 {
			t.Fatal("pending lifecycle admitted traffic", n, err)
		}
	}
	b.Drain = func(context.Context, []string) error { return nil }
	rb, err := controlRequest(t, b, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared = []quotaescrow.ControlReceipt{ra, rb}
	for _, node := range []*MeshControl{a, b} {
		if _, err := controlRequest(t, node, authority, plan, "commit", &policy, prepared); err != nil {
			t.Fatal(err)
		}
		ledger, err := quotaescrow.NewStore(node.DB).Load(plan.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		used, err := ledger.Billed()
		if err != nil || used != 300 {
			t.Fatal("renewal omitted/doubled disconnected usage", used, err)
		}
	}
}

func TestMeshControlResetClearsCardsButRenewalPreservesThem(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	detail := model.InboundTrafficDetail{Email: "phone", InboundTag: "one", RateParts: 1000000, RawUp: 30, RawDown: 70, BilledUp: 30, BilledDown: 70}
	if err := c.DB.Create(&detail).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.DB.Create(&model.InboundTrafficHistory{Bucket: 1, InboundTrafficDetail: detail}).Error; err != nil {
		t.Fatal(err)
	}
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, AlreadyBilled: 100, Grants: map[string]int64{"local": 900}, Keys: map[string][]byte{"local": c.Key.Public().(ed25519.PublicKey)}}
	for _, kind := range []string{"enroll", "renew", "reset"} {
		if kind != "enroll" {
			plan.ID = kind
			plan.Kind = kind
			plan.Epoch = policy.Epoch
			plan.NextEpoch = kind
		}
		r, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy.Epoch = plan.NextEpoch
		if kind == "reset" {
			policy.AlreadyBilled = 0
			policy.Grants["local"] = 1000
		}
		if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{r}); err != nil {
			t.Fatal(err)
		}
		var history int64
		c.DB.Model(&model.InboundTrafficHistory{}).Count(&history)
		var stats xray.ClientTraffic
		if err := c.DB.First(&stats, "email = ?", "phone").Error; err != nil {
			t.Fatal(err)
		}
		var source model.LocalUsage
		if err := c.DB.First(&source, "email = ?", "phone").Error; err != nil {
			t.Fatal(err)
		}
		if source.Billed != 900 || source.Source != "stable" {
			t.Fatal("lifetime meter reset")
		}
		if kind == "reset" {
			if history != 0 || stats.Up+stats.Down != 0 {
				t.Fatal("reset left old cards/usage", history, stats)
			}
		} else if history != 1 || stats.Up+stats.Down != 100 {
			t.Fatal("renewal erased previous usage", history, stats)
		}
	}
}
