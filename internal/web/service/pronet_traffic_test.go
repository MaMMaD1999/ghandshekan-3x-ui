package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
	"testing"
	"time"
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

func TestProNetTrafficHistoryBucketsAccumulateWithoutChangingLifetimeSemantics(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	start := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).UnixMilli()
	detail := model.InboundTrafficDetail{InboundName: "Germany", InboundTag: "in-2087-tcp", Email: "history-user", OriginGuid: "node-de", RateParts: 2_000_000, UpdatedAt: start + 10_000}
	for i := 0; i < 2; i++ {
		if err := db.Transaction(func(tx *gorm.DB) error {
			return recordTrafficHistory(tx, detail, 100, 200, 200, 400)
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, earliest, err := ProNetTrafficRange([]string{"history-user"}, start, start+60_000)
	if err != nil {
		t.Fatal(err)
	}
	if earliest != start || len(rows) != 1 {
		t.Fatalf("earliest=%d rows=%+v", earliest, rows)
	}
	got := rows[0]
	if got.InboundTag != detail.InboundTag || got.InboundName != detail.InboundName || got.RawUp != 200 || got.RawDown != 400 || got.BilledUp != 400 || got.BilledDown != 800 {
		t.Fatalf("unexpected bucket aggregation: %+v", got)
	}
	rows, _, err = ProNetTrafficRange([]string{"history-user"}, start+60_000, start+120_000)
	if err != nil || len(rows) != 0 {
		t.Fatalf("out-of-range rows=%+v err=%v", rows, err)
	}
}

func TestProNetRepeatedPollsAccumulateIncludingFreeRate(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	for _, rate := range []float64{0, 0.3, 3} {
		ib := &model.Inbound{Tag: "repeated", Protocol: model.VLESS, TrafficCoefficient: &rate}
		if err := db.Where("tag = ?", ib.Tag).Delete(&model.Inbound{}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(ib).Error; err != nil {
			t.Fatal(err)
		}
		var charged int64
		for i := 0; i < 10; i++ {
			rows, err := weightDetailedTraffic(db, []*xray.ClientTraffic{{Email: "repeat", Up: 1}, {Email: "repeat", InboundTag: ib.Tag, Up: 1}})
			if err != nil {
				t.Fatal(err)
			}
			charged += rows[0].Up
		}
		var row model.InboundTrafficDetail
		if err := db.Where("inbound_tag = ? AND rate_parts = ?", ib.Tag, int64(rate*1000000)).Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.RawUp != 10 || row.BilledUp != int64(10*rate) || charged != row.BilledUp {
			t.Fatalf("rate %v: %+v, charged %v", rate, row, charged)
		}
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

func TestProNetMixedSidecarIdentityIsPreserved(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	sidecar := &xray.ClientTraffic{Email: "same", TuicTrafficID: 12, Up: 20}
	rows, err := weightDetailedTraffic(db, []*xray.ClientTraffic{
		sidecar, {Email: "same", Up: 50}, {Email: "same", InboundTag: "deleted", Up: 50},
	})
	if err != nil || len(rows) != 2 || rows[0] != sidecar || rows[1].Up != 50 {
		t.Fatalf("sidecar identity or independent usage lost: %+v, %v", rows, err)
	}
}

func TestProNetWeightedQuotaAndRateHistory(t *testing.T) {
	setupBulkDB(t)
	db := database.GetDB()
	svc := &InboundService{}
	ib := mkInbound(t, 28999, model.VLESS, `{"clients":[]}`)
	_, err := (&ClientService{}).Create(svc, &ClientCreatePayload{
		Client:     model.Client{Email: "quota@pronet", ID: "a0000000-0000-0000-0000-000000000099", Enable: true, TotalGB: 4500},
		InboundIds: []int{ib.Id},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rate := range []float64{3, 2} {
		if err := db.Model(ib).Update("traffic_coefficient", rate).Error; err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.AddTraffic(nil, []*xray.ClientTraffic{
			{Email: "quota@pronet", Down: 1000},
			{Email: "quota@pronet", InboundTag: ib.Tag, Down: 1000},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := audit3Traffic(t, "quota@pronet")
	if got.Down != 5000 || got.Enable {
		t.Fatalf("quota must be billed and disabled: %+v", got)
	}
	var rows []model.InboundTrafficDetail
	if err := db.Where("email = ?", "quota@pronet").Order("rate_parts").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].RawDown != 1000 || rows[0].BilledDown != 2000 || rows[1].RawDown != 1000 || rows[1].BilledDown != 3000 {
		t.Fatalf("history must preserve both rates: %+v", rows)
	}
}
