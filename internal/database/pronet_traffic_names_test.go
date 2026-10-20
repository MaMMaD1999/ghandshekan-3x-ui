package database

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
)

func TestProNetTrafficNameBackfillPreservesCountersAndPhysicalOrigin(t *testing.T) {
	original := db
	t.Cleanup(func() { db = original })
	var err error
	db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []any{&model.Inbound{}, &model.InboundTrafficDetail{}, &model.InboundTrafficHistory{}} {
		if err := db.AutoMigrate(row); err != nil {
			t.Fatal(err)
		}
	}
	ib := model.Inbound{Tag: "in-443-tcp", Remark: "Germany", Protocol: model.VLESS}
	if err := db.Create(&ib).Error; err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "other-node"} {
		row := model.InboundTrafficDetail{InboundTag: ib.Tag, OriginGuid: origin, Email: "subscriber", RawDown: 100, BilledDown: 300, RateParts: 3000000}
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.InboundTrafficHistory{Bucket: 60000, InboundTrafficDetail: row}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := backfillProNetTrafficNames(); err != nil {
			t.Fatal(err)
		}
	}
	var rows []model.InboundTrafficDetail
	if err := db.Order("origin_guid").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].InboundName != "Germany" || rows[1].InboundName != "" || rows[0].BilledDown != 300 || rows[0].RawDown != 100 {
		t.Fatalf("backfill changed attribution or counters: %+v", rows)
	}
	var history model.InboundTrafficHistory
	db.Where("origin_guid = ?", "").First(&history)
	if history.InboundName != "Germany" || history.BilledDown != 300 {
		t.Fatalf("history: %+v", history)
	}
}
