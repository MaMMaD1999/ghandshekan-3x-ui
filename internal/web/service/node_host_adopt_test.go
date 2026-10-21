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

	// Later node snapshots must leave the imported hosts under master control.
	snap.HostGroups[0].Hosts = []string{"updated.example.com:9443"}
	snap.HostGroups[0].Sni = "updated.example.com"
	if _, err := svc.setRemoteTrafficLocked(nodeID, snap, false, false); err != nil {
		t.Fatalf("sync updated host snapshot: %v", err)
	}
	if err := db.Where("inbound_id = ?", central.Id).Find(&hosts).Error; err != nil {
		t.Fatalf("load updated adopted hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Address != "cdn.example.com" || hosts[0].Port != 8443 || hosts[0].Sni != "sni.example.com" {
		t.Fatalf("updated adopted hosts = %+v", hosts)
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
		rows := adoptedHostRows(groups, i+1, 52, inbound.Id)
		if err := db.Create(&rows).Error; err != nil {
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
