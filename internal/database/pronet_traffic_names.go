package database

import "github.com/mhsanaei/3x-ui/v3/internal/database/model"

// Early releases stored labels only at read time. Persist those still known
// before an inbound can disappear; historical byte counters stay untouched.
func backfillProNetTrafficNames() error {
	var inbounds []model.Inbound
	if err := db.Select("tag", "remark", "origin_node_guid", "node_id").Where("TRIM(COALESCE(remark,'')) <> ''").Find(&inbounds).Error; err != nil {
		return err
	}
	for _, ib := range inbounds {
		origin := ib.OriginNodeGuid
		if ib.NodeID == nil {
			origin = ""
		}
		for _, table := range []any{&model.InboundTrafficDetail{}, &model.InboundTrafficHistory{}} {
			if err := db.Model(table).Where("origin_guid = ? AND inbound_tag = ? AND (inbound_name IS NULL OR inbound_name <> ?)", origin, ib.Tag, ib.Remark).Update("inbound_name", ib.Remark).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
