package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/entity"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
)

func TestSetRemoteTraffic_AdoptsNodeHostRows(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()

	const nodeID = 6
	if err := db.Create(&model.Node{
		Id:       nodeID,
		Name:     "host-node",
		Address:  "10.0.0.6",
		Port:     2053,
		ApiToken: "t",
		Guid:     "host-node-guid",
	}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	snap := &runtime.TrafficSnapshot{
		Inbounds: []*model.Inbound{{
			Id:       77,
			Tag:      "host-adopt-443",
			Enable:   true,
			Port:     443,
			Protocol: model.VLESS,
			Settings: `{"clients":[]}`,
		}},
		HostGroups: []*entity.HostGroup{{
			GroupId:     "g-node",
			InboundIds:  []int{77, 99},
			Hosts:       []string{"cdn.example.com:8443"},
			Remark:      "cdn",
			Security:    "tls",
			Sni:         "sni.example.com",
			Fingerprint: "firefox",
		}},
	}

	svc := InboundService{}
	if _, err := svc.setRemoteTrafficLocked(nodeID, snap, false, false); err != nil {
		t.Fatalf("setRemoteTrafficLocked: %v", err)
	}

	var central model.Inbound
	if err := db.Where("tag = ?", "host-adopt-443").First(&central).Error; err != nil {
		t.Fatalf("load adopted inbound: %v", err)
	}
	var hosts []model.Host
	if err := db.Where("inbound_id = ?", central.Id).Find(&hosts).Error; err != nil {
		t.Fatalf("load adopted hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("adopted host rows = %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.GroupId != "node-6-g-node" || h.Address != "cdn.example.com" || h.Port != 8443 ||
		h.Security != "tls" || h.Sni != "sni.example.com" || h.Fingerprint != "firefox" || h.Remark != "cdn" {
		t.Fatalf("adopted host mismatch: %+v", h)
	}

	var total int64
	if err := db.Model(&model.Host{}).Count(&total).Error; err != nil {
		t.Fatalf("count hosts: %v", err)
	}
	if total != 1 {
		t.Fatalf("total host rows = %d, want 1 (group member for un-adopted node inbound 99 must not materialize)", total)
	}

	// Subsequent snapshots must mirror edits on the already-adopted inbound,
	// instead of leaving the ProNet subscription on the first host set forever.
	snap.HostGroups[0].Hosts = []string{"updated.example.com:9443"}
	snap.HostGroups[0].Sni = "updated.example.com"
	if _, err := svc.setRemoteTrafficLocked(nodeID, snap, false, false); err != nil {
		t.Fatalf("sync updated host snapshot: %v", err)
	}
	if err := db.Where("inbound_id = ?", central.Id).Find(&hosts).Error; err != nil {
		t.Fatalf("load updated adopted hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Address != "updated.example.com" || hosts[0].Port != 9443 || hosts[0].Sni != "updated.example.com" {
		t.Fatalf("updated adopted hosts = %+v", hosts)
	}
}

func TestSyncAdoptedHostRows_UpdatesAndRemovesStaleHosts(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	seedInboundConflict(t, "host-sync-443", "", 443, model.VLESS, `{}`, `{"clients":[]}`)
	var inbound model.Inbound
	if err := db.Where("tag = ?", "host-sync-443").First(&inbound).Error; err != nil {
		t.Fatalf("load inbound: %v", err)
	}
	groups := []*entity.HostGroup{{
		GroupId: "remote-group", InboundIds: []int{77}, Hosts: []string{"old.example:443"},
		Remark: "edge", Security: "tls", Sni: "old.example",
	}}
	changed, err := syncAdoptedHostRows(db, groups, 7, 77, inbound.Id)
	if err != nil || !changed {
		t.Fatalf("initial sync = (%v, %v), want changed", changed, err)
	}
	groups[0].Hosts = []string{"new.example:8443"}
	groups[0].Sni = "new.example"
	changed, err = syncAdoptedHostRows(db, groups, 7, 77, inbound.Id)
	if err != nil || !changed {
		t.Fatalf("updated sync = (%v, %v), want changed", changed, err)
	}
	var rows []model.Host
	if err := db.Where("inbound_id = ?", inbound.Id).Find(&rows).Error; err != nil {
		t.Fatalf("load updated hosts: %v", err)
	}
	if len(rows) != 1 || rows[0].Address != "new.example" || rows[0].Port != 8443 || rows[0].Sni != "new.example" {
		t.Fatalf("updated host rows = %+v", rows)
	}
	changed, err = syncAdoptedHostRows(db, []*entity.HostGroup{}, 7, 77, inbound.Id)
	if err != nil || !changed {
		t.Fatalf("empty sync = (%v, %v), want stale rows removed", changed, err)
	}
	if err := db.Where("inbound_id = ?", inbound.Id).Find(&rows).Error; err != nil {
		t.Fatalf("load removed hosts: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("host rows after removal = %+v, want none", rows)
	}
}

func TestAdoptedHostGroups_AreNamespacedAcrossClonedNodes(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	seedInboundConflict(t, "node-a-443", "", 443, model.VLESS, `{}`, `{"clients":[]}`)
	seedInboundConflict(t, "node-b-443", "", 443, model.VLESS, `{}`, `{"clients":[]}`)
	var inbounds []model.Inbound
	if err := db.Where("tag IN ?", []string{"node-a-443", "node-b-443"}).Order("id asc").Find(&inbounds).Error; err != nil {
		t.Fatalf("load inbounds: %v", err)
	}
	if len(inbounds) != 2 {
		t.Fatalf("inbounds = %d, want 2", len(inbounds))
	}
	groups := []*entity.HostGroup{{
		GroupId: "cloned-db-group", InboundIds: []int{52}, Hosts: []string{"node.example:443"}, Remark: "same-id",
	}}
	for i, inbound := range inbounds {
		groups[0].Hosts = []string{[]string{"a.example:443", "b.example:443"}[i]}
		if _, err := syncAdoptedHostRows(db, groups, i+1, 52, inbound.Id); err != nil {
			t.Fatalf("sync node %d hosts: %v", i+1, err)
		}
	}
	for i, inbound := range inbounds {
		got, err := (&HostService{}).GetHostsByInbound(inbound.Id)
		if err != nil {
			t.Fatalf("GetHostsByInbound(%d): %v", inbound.Id, err)
		}
		if len(got) != 1 || len(got[0].Hosts) != 1 || got[0].Hosts[0] != []string{"a.example:443", "b.example:443"}[i] {
			t.Fatalf("node %d host groups = %+v", i+1, got)
		}
	}
}
