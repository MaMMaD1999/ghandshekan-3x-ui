package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshParentSnapshotPreservesLifetimeRowsAcrossReset(t *testing.T) {
	c, p, keys := membershipFixture(t)
	store := quotaescrow.NewStore(c.DB)
	if err := store.ObserveMeter(p.Subscription, c.Owner, "missing-source", c.Key, 5); err == nil {
		t.Fatal("test must not create an invented meter")
	}
	if err := recordMeshLocalUsage(c.DB, "phone", 17, 0); err != nil {
		t.Fatal(err)
	}
	if failures, err := SettleMeshMeters(c.DB, func(string) (ed25519.PrivateKey, error) { return c.Key, nil }); err != nil || len(failures) > 0 {
		t.Fatal(failures, err)
	}
	reports, err := ReadMeshAccounts(c.DB, []string{p.Subscription})
	if err != nil || len(reports) != 1 || reports[0].Billed != 117 || reports[0].Rows[0].LifetimeUsed != 17 {
		t.Fatal(reports, err)
	}
	before, _ := json.Marshal(reports)
	for _, forbidden := range []string{"privateKey", "controlKeys", "fingerprint", "signature", "credential", "phone"} {
		if strings.Contains(string(before), forbidden) {
			t.Fatal("accounting response leaked identity material", forbidden)
		}
	}
	// Reset clears the visible billing cycle and preserves lifetime sources.
	u, err := quotaescrow.DraftPolicyChange(p, "snapshot-reset", "reset", quotaescrow.ControlTarget{Limit: p.Limit})
	if err != nil {
		t.Fatal(err)
	}
	u.Votes = map[string][]byte{}
	for _, owner := range []string{"a", "b"} {
		u.Votes[owner] = quotaescrow.PolicyUpdateVote(u, keys[owner])
	}
	if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{u}); err != nil {
		t.Fatal(err)
	}
	reports, err = ReadMeshAccounts(c.DB, []string{p.Subscription})
	if err != nil || len(reports) != 1 || reports[0].Billed != 0 || reports[0].InitialBilled != 0 || reports[0].ResetGeneration != 2 || reports[0].Rows[0].LifetimeUsed != 17 || reports[0].Rows[0].ResetAt != 17 {
		t.Fatal("reset lost lifetime or retained old-cycle usage", reports, err)
	}
	if reports[0].Epoch != p.Epoch || !reflect.DeepEqual(reports[0].Members, []string{"a", "b", "c"}) {
		t.Fatal("reset changed accounting identity", reports)
	}
}

func TestMeshParentSnapshotNeverTreatsMissingOrCorruptAsZero(t *testing.T) {
	c, p, _ := membershipFixture(t)
	for _, ids := range [][]string{nil, {p.Subscription, p.Subscription}, {p.Subscription, "missing"}, {"\x00"}, make([]string, 101)} {
		if reports, err := ReadMeshAccounts(c.DB, ids); err == nil || reports != nil {
			t.Fatal("unsafe partial/empty accounting report", reports, err)
		}
	}
	if err := c.DB.Model(&quotaescrow.Record{}).Where("subscription = ?", p.Subscription).Update("rows_json", "invalid").Error; err != nil {
		t.Fatal(err)
	}
	if reports, err := ReadMeshAccounts(c.DB, []string{p.Subscription}); err == nil || reports != nil {
		t.Fatal("corrupt counters became zero", reports, err)
	}
}
