package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func recordTrafficHistory(tx *gorm.DB, detail model.InboundTrafficDetail, up, down, billedUp, billedDown int64) error {
	if !tx.Migrator().HasTable(&model.InboundTrafficHistory{}) {
		return nil // upstream test fixtures may intentionally omit ProNet tables
	}
	if up == 0 && down == 0 && billedUp == 0 && billedDown == 0 {
		return nil
	}
	detail.RawUp, detail.RawDown, detail.BilledUp, detail.BilledDown = up, down, billedUp, billedDown
	detail.RemainderUp, detail.RemainderDown = 0, 0
	row := model.InboundTrafficHistory{Bucket: detail.UpdatedAt / 60000 * 60000, InboundTrafficDetail: detail}
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "bucket"}, {Name: "rate_parts"}, {Name: "origin_guid"}, {Name: "inbound_tag"}, {Name: "email"}},
		DoUpdates: clause.Assignments(map[string]any{
			"raw_up":       gorm.Expr("inbound_traffic_histories.raw_up + ?", up),
			"raw_down":     gorm.Expr("inbound_traffic_histories.raw_down + ?", down),
			"billed_up":    gorm.Expr("inbound_traffic_histories.billed_up + ?", billedUp),
			"billed_down":  gorm.Expr("inbound_traffic_histories.billed_down + ?", billedDown),
			"inbound_name": detail.InboundName, "updated_at": detail.UpdatedAt,
		}),
	}).Create(&row).Error
}

func nameTrafficRows(db *gorm.DB, rows []model.InboundTrafficDetail) {
	var inbounds []model.Inbound
	if db.Select("tag", "remark", "origin_node_guid", "node_id").Find(&inbounds).Error != nil {
		return
	}
	names := make(map[string]string)
	for _, ib := range inbounds {
		origin := ib.OriginNodeGuid
		if ib.NodeID == nil {
			origin = ""
		}
		names[origin+"\x00"+ib.Tag] = ib.Remark
	}
	for i := range rows {
		if name := names[rows[i].OriginGuid+"\x00"+rows[i].InboundTag]; name != "" {
			rows[i].InboundName = name
		}
	}
}

// Half-open UTC minute range, restricted to the subscription's resolved users.
// Mirrored samples use the source's last observation time; resolution is the
// polling interval, not individual packet time, especially after an outage.
func ProNetTrafficRange(emails []string, from, until int64) ([]model.InboundTrafficDetail, int64, error) {
	rows := make([]model.InboundTrafficDetail, 0)
	if len(emails) == 0 {
		return rows, 0, nil
	}
	db := database.GetDB()
	var first struct{ Start int64 }
	if err := db.Model(&model.InboundTrafficHistory{}).Select("COALESCE(MIN(bucket),0) AS start").Where("email IN ?", emails).Scan(&first).Error; err != nil {
		return nil, 0, err
	}
	err := db.Model(&model.InboundTrafficHistory{}).
		Select("origin_guid,inbound_tag,email,rate_parts,MAX(inbound_name) AS inbound_name,SUM(raw_up) AS raw_up,SUM(raw_down) AS raw_down,SUM(billed_up) AS billed_up,SUM(billed_down) AS billed_down").
		Where("email IN ? AND bucket >= ? AND bucket < ?", emails, from, until).
		Group("origin_guid,inbound_tag,email,rate_parts").Order("origin_guid,inbound_tag,email,rate_parts").Scan(&rows).Error
	if err == nil {
		nameTrafficRows(db, rows)
	}
	return rows, first.Start, err
}
