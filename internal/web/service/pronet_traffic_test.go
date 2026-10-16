package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"testing"
)

func TestProNetFractionalRemainder(t *testing.T) {
	var total, rem int64
	for i := 0; i < 10; i++ {
		b, r, err := weightedCounter(1, 300000, rem)
		if err != nil {
			t.Fatal(err)
		}
		total += b
		rem = r
	}
	if total != 3 || rem != 0 {
		t.Fatal(total, rem)
	}
	b, _, err := weightedCounter(100, 0, 0)
	if err != nil || b != 0 {
		t.Fatal("free traffic", b, err)
	}
}
func TestProNetSharedIdentityWeightedOnce(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	a, b := float64(3), float64(0.5)
	for _, ib := range []*model.Inbound{{Tag: "one", Protocol: model.VLESS, TrafficCoefficient: &a}, {Tag: "two", Protocol: model.VLESS, TrafficCoefficient: &b}} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatal(err)
		}
	}
	rows, err := weightDetailedTraffic(db, []*xray.ClientTraffic{
		{Email: "same", Up: 140}, {Email: "same", InboundTag: "one", Up: 100}, {Email: "same", InboundTag: "two", Up: 40},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Up != 320 {
		t.Fatal(rows)
	}
	var details []model.InboundTrafficDetail
	if err := db.Find(&details).Error; err != nil {
		t.Fatal(err)
	}
	var raw, billed int64
	for _, d := range details {
		raw += d.RawUp
		billed += d.BilledUp
	}
	if raw != 140 || billed != 320 {
		t.Fatal(raw, billed)
	}
}
func TestProNetLegacyRowsPreserveIdentityMetadata(t *testing.T) {
	rows := []*xray.ClientTraffic{{Email: "a", Up: 20}, {Email: "a", Down: 10}}
	out, err := weightDetailedTraffic(nil, rows)
	if err != nil || len(out) != 2 || out[0] != rows[0] {
		t.Fatal("ordinary counters modified", err)
	}
}
