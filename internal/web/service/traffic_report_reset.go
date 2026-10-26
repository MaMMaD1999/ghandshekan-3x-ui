package service

import (
	"fmt"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

func resetTrafficReports(tx *gorm.DB, emails ...string) error {
	if !tx.Migrator().HasTable(&model.InboundTrafficReportBaseline{}) {
		return nil
	}
	q := tx.Model(&model.InboundTrafficDetail{})
	history := tx.Where("1 = 1")
	if len(emails) > 0 {
		q = q.Where("email IN ?", emails)
		history = tx.Where("email IN ?", emails)
	}
	var rows []model.InboundTrafficDetail
	if err := q.Find(&rows).Error; err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	for _, row := range rows {
		baseline := model.InboundTrafficReportBaseline{InboundTrafficDetail: row, ResetAt: now}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&baseline).Error; err != nil {
			return err
		}
	}
	if tx.Migrator().HasTable(&model.InboundTrafficHistory{}) {
		return history.Delete(&model.InboundTrafficHistory{}).Error
	}
	return nil
}

func reportKey(row model.InboundTrafficDetail) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", row.OriginGuid, row.InboundTag, row.Email, row.RateParts)
}

func applyTrafficReportBaselines(db *gorm.DB, rows []model.InboundTrafficDetail, emails []string) {
	if len(rows) == 0 || !db.Migrator().HasTable(&model.InboundTrafficReportBaseline{}) {
		return
	}
	var baselines []model.InboundTrafficReportBaseline
	if db.Where("email IN ?", emails).Find(&baselines).Error != nil {
		return
	}
	byKey := make(map[string]model.InboundTrafficDetail, len(baselines))
	for _, b := range baselines {
		byKey[reportKey(b.InboundTrafficDetail)] = b.InboundTrafficDetail
	}
	for i := range rows {
		if b, ok := byKey[reportKey(rows[i])]; ok {
			rows[i].RawUp = max(int64(0), rows[i].RawUp-b.RawUp)
			rows[i].RawDown = max(int64(0), rows[i].RawDown-b.RawDown)
			rows[i].BilledUp = max(int64(0), rows[i].BilledUp-b.BilledUp)
			rows[i].BilledDown = max(int64(0), rows[i].BilledDown-b.BilledDown)
		}
	}
}
