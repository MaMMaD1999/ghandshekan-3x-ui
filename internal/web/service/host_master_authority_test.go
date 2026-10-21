package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/entity"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
)

// Node traffic polling must never undo host CRUD performed on the master,
// including deletion of an imported group and a group spanning local + node inbounds.
func TestNodeTrafficSnapshotsPreserveMasterHostCRUD(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	const nodeID = 6
	if err := db.Create(&model.Node{Id: nodeID, Name: "host-node", Address: "10.0.0.6", Port: 2053, ApiToken: "t", Guid: "host-node-guid"}).Error; err != nil {
		t.Fatal(err)
	}
	snap := &runtime.TrafficSnapshot{
		Inbounds:   []*model.Inbound{{Id: 77, Tag: "master-host-443", Enable: true, Port: 443, Protocol: model.VLESS, Settings: `{"clients":[]}`}},
		HostGroups: []*entity.HostGroup{{GroupId: "source", InboundIds: []int{77}, Hosts: []string{"original.example:443"}}},
	}
	svc := InboundService{}
	poll := func() {
		t.Helper()
		if _, err := svc.setRemoteTrafficLocked(nodeID, snap, false, false); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	var adopted model.Inbound
	if err := db.Where("tag = ?", "master-host-443").First(&adopted).Error; err != nil {
		t.Fatal(err)
	}
	seedInboundConflict(t, "master-local-8443", "", 8443, model.VLESS, `{}`, `{"clients":[]}`)
	var local model.Inbound
	if err := db.Where("tag = ?", "master-local-8443").First(&local).Error; err != nil {
		t.Fatal(err)
	}
	hosts := HostService{}
	if _, err := hosts.UpdateHostGroup("node-6-source", &entity.HostGroup{
		InboundIds: []int{adopted.Id}, Hosts: []string{"master-edited.example:9443"}, Sni: "master-sni.example",
	}); err != nil {
		t.Fatal(err)
	}
	created, err := hosts.AddHostGroup(&entity.HostGroup{
		InboundIds: []int{adopted.Id, local.Id}, Hosts: []string{"master-new.example:443"}, Remark: "Master choice",
	})
	if err != nil || len(created) != 2 {
		t.Fatalf("add spanning group: %v, %v", created, err)
	}
	groupID := created[0].GroupId
	if err := hosts.SetHostGroupEnable("node-6-source", false); err != nil {
		t.Fatal(err)
	}
	if err := hosts.ReorderHostGroups([]string{groupID, "node-6-source"}); err != nil {
		t.Fatal(err)
	}
	for _, snapshotGroups := range [][]*entity.HostGroup{snap.HostGroups, {}, {
		{GroupId: "source", InboundIds: []int{77}, Hosts: []string{"node-changed.example:443"}},
	}} {
		snap.HostGroups = snapshotGroups
		poll()
		g, err := hosts.GetHostGroup("node-6-source")
		if err != nil {
			t.Fatalf("master-edited imported group disappeared: %v", err)
		}
		if len(g.Hosts) != 1 || g.Hosts[0] != "master-edited.example:9443" || g.Sni != "master-sni.example" || !g.IsDisabled || g.SortOrder != 1 {
			t.Fatalf("poll overwrote master host edit/disable/order: %+v", g)
		}
		g, err = hosts.GetHostGroup(groupID)
		if err != nil || len(g.InboundIds) != 2 {
			t.Fatalf("poll removed a master-created group association: %+v, %v", g, err)
		}
	}
	if err := hosts.DeleteHostsGroup([]string{groupID, "node-6-source"}); err != nil {
		t.Fatal(err)
	}
	poll()
	var count int64
	if err := db.Model(&model.Host{}).Where("inbound_id IN ?", []int{adopted.Id, local.Id}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("poll resurrected deleted master host rows: %d", count)
	}
}
