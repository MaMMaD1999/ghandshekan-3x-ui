package model

import "gorm.io/gorm"

// All creation paths (CRUD, import, migration and node adoption) use the same
// transaction. Deleting the last host must never revive an old proxy or a raw
// endpoint. No host rows or runtime transport settings are modified here.
func (h *Host) AfterCreate(tx *gorm.DB) error {
	return tx.Model(&Inbound{}).Where("id = ?", h.InboundId).UpdateColumn("hosts_managed", true).Error
}
