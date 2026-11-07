package service

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

// commitMeshClientPolicy runs in the SAME transaction as the epoch commit. A
// renewal preserves counters/cards; a reset clears displayed usage and cards,
// while the monotonic mesh_local_usage source is deliberately never reset.
func commitMeshClientPolicy(tx *gorm.DB, p quotaescrow.Policy, kind string, emails []string) error {
	if p.ExpiresAt > math.MaxInt64/1000 {
		return errors.New("expiry exceeds panel timestamp range")
	}
	// A pushed display total from an older epoch cannot survive any cutover.
	if err := clearGlobalTraffic(tx, emails...); err != nil {
		return err
	}
	if kind == "reset" {
		if err := resetTrafficReports(tx, emails...); err != nil {
			return err
		}
		if err := adjustGroupBaselinesForRemovedTraffic(tx, emails); err != nil {
			return err
		}
		if err := clearGlobalTraffic(tx, emails...); err != nil {
			return err
		}
		if err := tx.Where("email IN ?", emails).Delete(&model.NodeClientTraffic{}).Error; err != nil {
			return err
		}
	}
	var clients []model.ClientRecord
	if err := tx.Where("email IN ?", emails).Find(&clients).Error; err != nil {
		return err
	}
	if len(clients) != len(emails) {
		return errors.New("enrolled client disappeared")
	}
	byEmail := map[string]model.ClientRecord{}
	for _, client := range clients {
		byEmail[client.Email] = client
		if err := tx.Model(&model.ClientRecord{}).Where("id = ?", client.Id).Updates(map[string]any{"total_gb": p.Limit, "expiry_time": p.ExpiresAt * 1000}).Error; err != nil {
			return err
		}
		changes := map[string]any{"total": p.Limit, "expiry_time": p.ExpiresAt * 1000, "enable": client.Enable}
		if kind == "reset" {
			changes["up"] = 0
			changes["down"] = 0
		}
		if err := tx.Model(&xray.ClientTraffic{}).Where("email = ?", client.Email).Updates(changes).Error; err != nil {
			return err
		}
	}
	var inbounds []model.Inbound
	if err := tx.Table("inbounds").Select("DISTINCT inbounds.*").Joins("JOIN client_inbounds ci ON ci.inbound_id = inbounds.id").Joins("JOIN clients c ON c.id = ci.client_id").Where("c.email IN ?", emails).Find(&inbounds).Error; err != nil {
		return err
	}
	for _, inbound := range inbounds {
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return err
		}
		entries, _ := settings["clients"].([]any)
		for _, entry := range entries {
			row, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			email, _ := row["email"].(string)
			client, ok := byEmail[email]
			if !ok {
				continue
			}
			row["totalGB"] = p.Limit
			row["expiryTime"] = p.ExpiresAt * 1000
			row["enable"] = client.Enable
		}
		encoded, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).Update("settings", string(encoded)).Error; err != nil {
			return err
		}
	}
	return nil
}
