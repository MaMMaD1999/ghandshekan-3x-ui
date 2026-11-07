package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
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
	if key == "" {
		// Existing integrations perform absolute client updates without a retry
		// header. Preserve that API, but pin this update to the observed policy:
		// it may not overwrite a newer majority decision from a stale replica.
		ledger, err := quotaescrow.NewStore(db).Load(binding.Subscription)
		if err != nil {
			return true, result, err
		}
		input, generated := legacyAbsoluteMeshRequest(ledger.Policy(), updated.TotalGB, expires, disabled, unlimited)
		receipt, err := QueueMeshParentPolicy(ctx, input, generated)
		return true, MeshOperationResult{Operation: receipt.Operation, Pending: receipt.ApplicationPending}, err
	}
	return TryMeshLifecycle(ctx, email, "renew", key, &updated.TotalGB, &expires, MeshAvailability{Disabled: &disabled, Unlimited: &unlimited})
}

func legacyAbsoluteMeshRequest(p quotaescrow.Policy, limit, expires int64, disabled, unlimited bool) (MeshParentPolicyInput, string) {
	input := MeshParentPolicyInput{Subscription: p.Subscription, ControlEpoch: p.ControlEpoch,
		Epoch: p.Epoch, ExpectedHash: quotaescrow.PolicyHash(p), Kind: "renew",
		Limit: limit, ExpiresAt: expires, Disabled: &disabled, Unlimited: &unlimited}
	encoded, _ := json.Marshal(input)
	h := sha256.Sum256(append([]byte("legacy-absolute-client/v1\x00"), encoded...))
	return input, "legacy-" + hex.EncodeToString(h[:])
}
