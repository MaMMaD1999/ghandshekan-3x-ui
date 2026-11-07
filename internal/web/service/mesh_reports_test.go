package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestMeshOldNodeSnapshotCannotResurrectResetUsage(t *testing.T) {
	db := initTrafficTestDB(t)
	seedNodeRow(t, db, &model.Node{Id: 1, Name: "child", Guid: "b", Address: "127.0.0.1", Port: 1234, Enable: true})
	createNodeInboundWithClient(t, db, 1, "node-one", 12345, "phone")
	svc := &InboundService{}
	settings := `{"clients":[{"email":"phone","id":"same-secret","enable":true,"totalGB":1000}]}`
	syncNodeWithSettings(t, svc, 1, "node-one", settings, xray.ClientTraffic{Email: "phone", Enable: true, Total: 1000})
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	p := quotaescrow.Policy{Subscription: "sub", Epoch: "new-cycle", Limit: 1000, Grants: map[string]int64{"a": 1000}, Keys: map[string][]byte{"a": key}}
	if err := quotaescrow.NewStore(db).Create(p); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.MeshBinding{Email: "phone", Subscription: "sub", Owner: "a"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("email = ?", "phone").Delete(&model.NodeClientTraffic{}).Error; err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		epoch          string
		reported, want int64
	}{{"old-cycle", 900, 0}, {"", 950, 0}, {"new-cycle", 7, 7}, {"new-cycle", 7, 7}, {"old-cycle", 999, 7}, {"new-cycle", 11, 11}} {
		snapshot := snapshotWithClients(t, "node-one", `{"clients":[{"email":"phone","id":"wrong-secret","enable":false,"totalGB":9000}]}`, xray.ClientTraffic{Email: "phone", Up: sample.reported, Total: 9000, MeshEpoch: sample.epoch})
		snapshot.Inbounds[0].DetailedTraffic = []model.InboundTrafficDetail{{Email: "phone", RateParts: coefficientScale, RawUp: sample.reported, BilledUp: sample.reported, UpdatedAt: sample.reported, MeshEpoch: sample.epoch}}
		if _, err := svc.SetRemoteTraffic(1, snapshot, false, false); err != nil {
			t.Fatal(err)
		}
		got := readTraffic(t, db, "phone")
		if got.Up != sample.want || got.Total != 1000 || !got.Enable {
			t.Fatal("stale report changed epoch/account", sample, got)
		}
		var client model.ClientRecord
		if err := db.Where("email = ?", "phone").First(&client).Error; err != nil {
			t.Fatal(err)
		}
		if client.UUID != "same-secret" || client.TotalGB != 1000 {
			t.Fatal("stale settings replaced managed client", client.TotalGB)
		}
	}
	var details []model.InboundTrafficDetail
	if err := db.Find(&details).Error; err != nil {
		t.Fatal(err)
	}
	if len(details) != 1 || details[0].BilledUp != 11 {
		t.Fatal("stale consumption card returned", details)
	}
	if err := svc.AcceptGlobalTraffic("b", []*xray.ClientTraffic{{Email: "phone", Up: 999, MeshEpoch: "old-cycle"}}); err != nil {
		t.Fatal(err)
	}
	var globals int64
	if err := db.Model(&model.ClientGlobalTraffic{}).Count(&globals).Error; err != nil || globals != 0 {
		t.Fatal("stale global overlay accepted", globals, err)
	}
	inbounds, err := svc.GetInbounds(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, inbound := range inbounds {
		for _, stat := range inbound.ClientStats {
			if stat.Email == "phone" && stat.MeshEpoch != p.Epoch {
				t.Fatal("outgoing snapshot epoch missing")
			}
		}
	}
}

func TestMeshSettingsPreserveManagedMembershipOnly(t *testing.T) {
	current := `{"clients":[{"email":"managed","id":"original"},{"email":"ordinary","id":"old"}]}`
	incoming := `{"clients":[{"email":"ordinary","id":"new"},{"email":"foreign","id":"no"}],"decryption":"none"}`
	result, err := preserveMeshSettings(current, incoming, map[string]meshReportScope{"managed": {Pending: true}, "foreign": {Epoch: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Clients []struct {
			Email string
			ID    string
		}
		Decryption string
	}
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Clients) != 2 || decoded.Clients[0].Email != "ordinary" || decoded.Clients[0].ID != "new" || decoded.Clients[1].Email != "managed" || decoded.Clients[1].ID != "original" || decoded.Decryption != "none" {
		t.Fatal(decoded)
	}
}
