package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
)

// TryMeshClientEdit routes ordinary quota/expiry/enable edits through the
// authority journal. Membership and credential changes remain separate: an
// inbound filter must never silently apply half a subscription's policy.
func TryMeshClientEdit(ctx context.Context, email string, updated model.Client, limitHwid int, key string) (bool, MeshOperationResult, error) {
	var result MeshOperationResult
	db := database.GetDB()
	if !db.Migrator().HasTable(&model.MeshBinding{}) {
		return false, result, nil
	}
	var binding model.MeshBinding
	if err := db.First(&binding, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, result, nil
		}
		return false, result, err
	}
	var existing model.ClientRecord
	if err := db.First(&existing, "email = ?", email).Error; err != nil {
		return true, result, err
	}
	before := existing.ToClient()
	if updated.ID == "" {
		updated.ID = before.ID
	}
	if updated.Password == "" {
		updated.Password = before.Password
	}
	if updated.Auth == "" {
		updated.Auth = before.Auth
	}
	if updated.Secret == "" {
		updated.Secret = before.Secret
	}
	if updated.SubID == "" {
		updated.SubID = before.SubID
	}
	if updated.Flow == "" {
		updated.Flow = before.Flow
	}
	if updated.Security == "" {
		updated.Security = before.Security
	}
	normalizeClientTrafficReset(&updated)
	normalizeClientTrafficReset(before)
	after := updated
	after.TotalGB, after.ExpiryTime, after.Enable = before.TotalGB, before.ExpiryTime, before.Enable
	after.CreatedAt, after.UpdatedAt = before.CreatedAt, before.UpdatedAt
	// Compare JSON representations, so omitted empty maps/slices are equivalent.
	encode := func(v any) map[string]any {
		b, _ := json.Marshal(v)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	if !reflect.DeepEqual(encode(before), encode(after)) || limitHwid != existing.LimitHwid {
		return true, result, errors.New("mesh quota edits cannot also change credentials, membership, metadata or schedules")
	}
	if updated.ExpiryTime < 0 {
		return true, result, errors.New("a mesh renewal requires a fixed expiry time")
	}
	expires := updated.ExpiryTime / 1000
	if updated.ExpiryTime%1000 != 0 {
		expires++
	}
	disabled, unlimited := !updated.Enable, updated.TotalGB == 0
	return TryMeshLifecycle(ctx, email, "renew", key, &updated.TotalGB, &expires, MeshAvailability{Disabled: &disabled, Unlimited: &unlimited})
}
