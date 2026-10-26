package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"testing"
)

func TestTrafficResetClearsCardsAndDatedHistoryButPreservesLifetime(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	if err := db.AutoMigrate(&model.InboundTrafficReportBaseline{}); err != nil {
		t.Fatal(err)
	}
	row := model.InboundTrafficDetail{Email: "report-reset", InboundTag: "in-2087-tcp", RateParts: 2000000, RawDown: 120, BilledDown: 240, UpdatedAt: 60000}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := recordTrafficHistory(db, row, 0, 120, 0, 240); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{Email: row.Email, Enable: true, Down: 240}).Error; err != nil {
		t.Fatal(err)
	}
	if err := (&InboundService{}).ResetClientTrafficByEmail(row.Email); err != nil {
		t.Fatal(err)
	}
	got := ProNetSubscriptionTraffic([]string{row.Email})
	if len(got) != 1 || got[0].RawDown != 0 || got[0].BilledDown != 0 {
		t.Fatalf("old card remains: %+v", got)
	}
	ranged, _, err := ProNetTrafficRange([]string{row.Email}, 0, 120000)
	if err != nil || len(ranged) != 0 {
		t.Fatalf("old range remains: %+v %v", ranged, err)
	}
	var lifetime model.InboundTrafficDetail
	if err := db.Where("email = ?", row.Email).First(&lifetime).Error; err != nil {
		t.Fatal(err)
	}
	if lifetime.RawDown != 120 || lifetime.BilledDown != 240 {
		t.Fatalf("billing checkpoint was changed: %+v", lifetime)
	}
	lifetime.RawDown += 10
	lifetime.BilledDown += 20
	if err := db.Save(&lifetime).Error; err != nil {
		t.Fatal(err)
	}
	got = ProNetSubscriptionTraffic([]string{row.Email})
	if len(got) != 1 || got[0].RawDown != 10 || got[0].BilledDown != 20 {
		t.Fatalf("new traffic is not isolated: %+v", got)
	}
}

func TestReportResetIsEmailScopedAndDoesNotResetRenewalHistory(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	if err := db.AutoMigrate(&model.InboundTrafficReportBaseline{}); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"reset-only", "keep-renewal"} {
		row := model.InboundTrafficDetail{Email: email, InboundTag: "in-443-tcp", RateParts: 1000000, RawDown: 100, BilledDown: 100, UpdatedAt: 60000}
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := resetTrafficReports(db, "reset-only"); err != nil {
		t.Fatal(err)
	}
	rows := ProNetSubscriptionTraffic([]string{"keep-renewal"})
	if len(rows) != 1 || rows[0].BilledDown != 100 {
		t.Fatalf("another account was affected: %+v", rows)
	}
}
