package database

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestManagedHostPolicySurvivesDeletionAndBackfill(t *testing.T) {
	initMigrateDB(t)
	old := seedInboundWithStream(t, "deleted-legacy", 4343, epMigrationStream)
	fresh := seedInboundWithStream(t, "fresh-direct", 4344, `{}`)
	hadHost := seedInboundWithStream(t, "deleted-modern", 4345, `{}`)
	host := &model.Host{InboundId: hadHost.Id, Address: "removed.example"}
	if err := GetDB().Create(host).Error; err != nil {
		t.Fatal(err)
	}
	if err := GetDB().Delete(host).Error; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := backfillManagedHosts(); err != nil {
			t.Fatal(err)
		}
		for _, ib := range []*model.Inbound{old, fresh, hadHost} {
			if err := GetDB().First(ib, ib.Id).Error; err != nil {
				t.Fatal(err)
			}
			if ib.HostsManaged != (ib.Id != fresh.Id) {
				t.Fatalf("%s managed=%v", ib.Tag, ib.HostsManaged)
			}
		}
	}
	var count int64
	GetDB().Model(&model.Host{}).Count(&count)
	if count != 0 {
		t.Fatalf("backfill resurrected %d deleted hosts", count)
	}
}
