package service

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

var errMeshLifecycleRequired = errors.New("this subscription is managed by mesh; use a coordinated lifecycle operation")

// Includes enrollment barriers before the first binding exists. Call inside
// the same serialized transaction as the proposed legacy mutation.
func meshManagedAliases(tx *gorm.DB) (map[string]bool, error) {
	out, err := meshPendingAliases(tx)
	if err != nil {
		return nil, err
	}
	if tx.Migrator().HasTable(&model.MeshBinding{}) {
		var emails []string
		if err := tx.Model(&model.MeshBinding{}).Pluck("email", &emails).Error; err != nil {
			return nil, err
		}
		for _, email := range emails {
			out[email] = true
		}
	}
	return out, nil
}

func requireLegacyAliases(tx *gorm.DB, emails ...string) error {
	managed, err := meshManagedAliases(tx)
	if err != nil {
		return err
	}
	if len(emails) == 0 && len(managed) > 0 {
		return errMeshLifecycleRequired
	}
	for _, email := range emails {
		if managed[email] {
			return errMeshLifecycleRequired
		}
	}
	return nil
}

func excludeMeshTraffic(tx *gorm.DB, rows []*xray.ClientTraffic) ([]*xray.ClientTraffic, error) {
	managed, err := meshManagedAliases(tx)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, row := range rows {
		if !managed[row.Email] {
			out = append(out, row)
		}
	}
	return out, nil
}

func requireMeshSettingsUnchanged(tx *gorm.DB, current, next string) error {
	managed, err := meshManagedAliases(tx)
	if err != nil || len(managed) == 0 {
		return err
	}
	parse := func(raw string) (map[string]map[string]any, error) {
		var body struct {
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			return nil, err
		}
		out := map[string]map[string]any{}
		for _, row := range body.Clients {
			email, _ := row["email"].(string)
			if !managed[email] {
				continue
			}
			if out[email] != nil {
				return nil, errors.New("duplicate mesh alias")
			}
			delete(row, "updated_at")
			out[email] = row
		}
		return out, nil
	}
	a, err := parse(current)
	if err != nil {
		return err
	}
	b, err := parse(next)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return errMeshLifecycleRequired
	}
	return nil
}

func requireMeshInboundIdentity(tx *gorm.DB, old, next *model.Inbound) error {
	if old.Tag == next.Tag && old.Protocol == next.Protocol && reflect.DeepEqual(old.NodeID, next.NodeID) {
		return nil
	}
	var emails []string
	if err := tx.Table("clients c").Joins("JOIN client_inbounds ci ON ci.client_id = c.id").Where("ci.inbound_id = ?", old.Id).Pluck("c.email", &emails).Error; err != nil {
		return err
	}
	if len(emails) == 0 {
		return nil
	}
	return requireLegacyAliases(tx, emails...)
}

func requireMeshRecordUnchanged(managed map[string]bool, before, after model.ClientRecord) error {
	if !managed[before.Email] && !managed[after.Email] {
		return nil
	}
	// These fields affect accounting, authentication, renewal or membership.
	type protected struct {
		Email, SubID, UUID, Password, Auth, Secret, Flow, Security, TrafficReset string
		TotalGB, ExpiryTime                                                      int64
		Enable                                                                   bool
		Reset, ResetDay, ResetWeekday, ResetMax, TrafficResetDay                 int
	}
	value := func(c model.ClientRecord) protected {
		return protected{c.Email, c.SubID, c.UUID, c.Password, c.Auth, c.Secret, c.Flow, c.Security, c.TrafficReset, c.TotalGB, c.ExpiryTime, c.Enable, c.Reset, c.ResetDay, c.ResetWeekday, c.ResetMax, c.TrafficResetDay}
	}
	if value(before) != value(after) {
		return errMeshLifecycleRequired
	}
	return nil
}

func requireMeshLinksUnchanged(tx *gorm.DB, inboundID int, clients []model.Client, detached []string, prune bool) error {
	managed, err := meshManagedAliases(tx)
	if err != nil || len(managed) == 0 {
		return err
	}
	var current []string
	if err := tx.Table("clients c").Joins("JOIN client_inbounds ci ON ci.client_id = c.id").Where("ci.inbound_id = ?", inboundID).Pluck("c.email", &current).Error; err != nil {
		return err
	}
	have, want := map[string]bool{}, map[string]bool{}
	for _, email := range current {
		have[email] = true
	}
	for _, client := range clients {
		want[client.Email] = true
		if managed[client.Email] && !have[client.Email] {
			return errMeshLifecycleRequired
		}
	}
	for _, email := range detached {
		if managed[email] && have[email] {
			return errMeshLifecycleRequired
		}
	}
	if prune {
		for email := range have {
			if managed[email] && !want[email] {
				return errMeshLifecycleRequired
			}
		}
	}
	return nil
}
