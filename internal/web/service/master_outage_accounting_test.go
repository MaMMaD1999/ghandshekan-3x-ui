package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"testing"
)

// No polls occur while the master is offline. Nodes send durable cumulative
// counters on reconnect; the next master instance must consume the gap once.
func TestMasterOutageCatchesUpWeightedNodeTrafficOnce(t *testing.T) {
	db := initTrafficTestDB(t)
	const email = "outage-fixture"
	createNodeInboundWithClient(t, db, 1, "at-in", 41001, email)
	createNodeInboundWithClient(t, db, 2, "nl-in", 41002, email)
	apply := func(svc *InboundService, node int, tag string, raw, rate, stamp int64) {
		t.Helper()
		snap := &runtime.TrafficSnapshot{Inbounds: []*model.Inbound{{
			Tag: tag, Settings: `{"clients":[{"email":"outage-fixture","enable":true}]}`,
			ClientStats:       []xray.ClientTraffic{{Email: email, Enable: true, Down: raw * rate}},
			AccountingVersion: 1,
			DetailedTraffic: []model.InboundTrafficDetail{{Email: email, InboundTag: tag,
				RawDown: raw, BilledDown: raw * rate, RateParts: rate * 1000000, UpdatedAt: stamp}},
		}}}
		if _, err := svc.setRemoteTrafficLocked(node, snap, false, false); err != nil {
			t.Fatal(err)
		}
	}
	apply(&InboundService{}, 1, "at-in", 0, 3, 1000)
	apply(&InboundService{}, 2, "nl-in", 0, 2, 1000)
	// Several hours of node usage accumulated without any successful master poll.
	restarted := &InboundService{}
	apply(restarted, 1, "at-in", 100000000, 3, 14400000)
	apply(restarted, 2, "nl-in", 200000000, 2, 14400000)
	assertUpDown(t, readTraffic(t, db, email), 0, 700000000, "offline gap")
	// Another service restart and replay of the exact same snapshot.
	apply(&InboundService{}, 1, "at-in", 100000000, 3, 14400000)
	apply(&InboundService{}, 2, "nl-in", 200000000, 2, 14400000)
	assertUpDown(t, readTraffic(t, db, email), 0, 700000000, "replay")
	var details []model.InboundTrafficDetail
	if err := db.Where("email = ?", email).Find(&details).Error; err != nil {
		t.Fatal(err)
	}
	var raw, billed int64
	for _, d := range details {
		raw += d.RawDown
		billed += d.BilledDown
	}
	if raw != 300000000 || billed != 700000000 {
		t.Fatalf("details raw=%d billed=%d", raw, billed)
	}
	apply(&InboundService{}, 1, "at-in", 110000000, 3, 14460000)
	assertUpDown(t, readTraffic(t, db, email), 0, 730000000, "subsequent delta")
}
