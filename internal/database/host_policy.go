package database

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// Mark existing catalogs, including migrated externalProxy arrays whose hosts
// were subsequently deleted. The one-time legacy seeder remains one-time: no
// deleted host is recreated, and no credentials or usage counters are changed.
func backfillManagedHosts() error {
	var inbounds []model.Inbound
	if err := db.Where("hosts_managed = ? OR hosts_managed IS NULL", false).Find(&inbounds).Error; err != nil {
		return err
	}
	for _, ib := range inbounds {
		var stream map[string]any
		_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
		legacy, _ := stream["externalProxy"].([]any)
		var count int64
		if err := db.Model(&model.Host{}).Where("inbound_id = ?", ib.Id).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 || len(legacy) > 0 {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).UpdateColumn("hosts_managed", true).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
