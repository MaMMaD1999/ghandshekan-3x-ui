package service

import (
	"crypto/ed25519"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshHistoricalReceiptPreservesSeedAndRejectsAlteredBaseline(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	plan.AccountingRoots = []quotaescrow.LegacyRoot{{Owner: c.Owner, Alias: "phone"}}
	r, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	billed, err := quotaescrow.PreparedHistoricalUsage(plan, []quotaescrow.ControlReceipt{r})
	if err != nil || billed != 100 {
		t.Fatal(billed, err)
	}
	p := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, AlreadyBilled: 99, Grants: map[string]int64{c.Owner: 901}, Keys: map[string][]byte{c.Owner: c.Key.Public().(ed25519.PublicKey)}}
	if _, err = controlRequest(t, c, authority, plan, "commit", &p, []quotaescrow.ControlReceipt{r}); err == nil {
		t.Fatal("accepted changed historical consumption")
	}
	p.AlreadyBilled = 100
	p.Grants[c.Owner] = 900
	if _, err = controlRequest(t, c, authority, plan, "commit", &p, []quotaescrow.ControlReceipt{r}); err != nil {
		t.Fatal(err)
	}
}

func TestMeshHistoricalRefusesUnfinishedLegacyReset(t *testing.T) {
	c, authority, plan, _ := controlFixture(t)
	if err := c.DB.Create(&model.NodePendingReset{NodeId: 123, Email: "phone", QueuedAt: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := controlRequest(t, c, authority, plan, "prepare", nil, nil); err == nil {
		t.Fatal("accepted pending legacy reset")
	}
}
