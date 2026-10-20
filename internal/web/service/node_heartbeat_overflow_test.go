package service

import (
	"math"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestHeartbeatInvalidNetworkCountersDoNotDiscardHealth(t *testing.T) {
	setupConflictDB(t)
	node := model.Node{Name: "counter-reset", Address: "127.0.0.1", Port: 2053}
	if err := database.GetDB().Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	err := (&NodeService{}).UpdateHeartbeat(node.Id, HeartbeatPatch{
		Status: "online", LastHeartbeat: 100, LatencyMs: 23,
		PanelVersion: "3.10.2-pronet.11", NetUp: math.MaxUint64, NetDown: 1234,
	})
	if err != nil {
		t.Fatalf("an old node's overflow must not prevent its health update: %v", err)
	}
	var got model.Node
	if err := database.GetDB().First(&got, node.Id).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != "online" || got.LatencyMs != 23 || got.PanelVersion != "3.10.2-pronet.11" || got.NetUp != 0 || got.NetDown != 1234 {
		t.Fatalf("health or valid traffic was lost: %+v", got)
	}
}
