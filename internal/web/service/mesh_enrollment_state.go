package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
)

// A separate enrollment-only guard: normal usage must not invalidate planning,
// while a concurrent renewal, disable, first-use activation or schedule edit
// must never be overwritten by the policy captured before that edit.
// Call inside the same transaction as the durable admission barrier.
func MeshEnrollmentState(tx *gorm.DB, email string) (string, error) {
	var client model.ClientRecord
	if err := tx.First(&client, "email = ?", email).Error; err != nil {
		return "", err
	}
	fingerprint, err := MeshAliasFingerprint(tx, email)
	if err != nil {
		return "", err
	}
	type inboundSchedule struct {
		ID              int
		TrafficReset    string
		TrafficResetDay int
	}
	var schedules []inboundSchedule
	if err := tx.Table("inbounds i").Select("i.id, i.traffic_reset, i.traffic_reset_day").Joins("JOIN client_inbounds ci ON ci.inbound_id = i.id").Where("ci.client_id = ?", client.Id).Order("i.id").Scan(&schedules).Error; err != nil {
		return "", err
	}
	var zone struct{ Value string }
	if err := tx.Table("settings").Select("value").Where("key = ?", "timeLocation").Scan(&zone).Error; err != nil {
		return "", err
	}
	state := struct {
		Fingerprint                             string
		Limit, ExpiresAt                        int64
		Enabled                                 bool
		Reset, ResetDay, ResetWeekday, ResetMax int
		TrafficReset                            string
		TrafficResetDay                         int
		Schedules                               []inboundSchedule
		Zone                                    string
	}{fingerprint, client.TotalGB, client.ExpiryTime, client.Enable, client.Reset, client.ResetDay, client.ResetWeekday, client.ResetMax, client.TrafficReset, client.TrafficResetDay, schedules, zone.Value}
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("ghandshekan/enrollment-state/v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}
