package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

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
	after.Comment, after.Group, after.TgID = before.Comment, before.Group, before.TgID
	after.LimitIP, after.AdTag = before.LimitIP, before.AdTag
	// Compare JSON representations, so omitted empty maps/slices are equivalent.
	encode := func(v any) map[string]any {
		b, _ := json.Marshal(v)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	if !reflect.DeepEqual(encode(before), encode(after)) {
		return true, result, errors.New("mesh credential, membership or schedule changes require a coordinated transition")
	}
	if updated.LimitIP < 0 || limitHwid < 0 {
		return true, result, errors.New("client device limits cannot be negative")
	}
	if updated.ExpiryTime < 0 {
		return true, result, errors.New("a mesh renewal requires a fixed expiry time")
	}
	expires := updated.ExpiryTime / 1000
	if updated.ExpiryTime%1000 != 0 {
		expires++
	}
	disabled, unlimited := !updated.Enable, updated.TotalGB == 0
	// Metadata must not generate a policy revision or interrupt a live stream.
	// It never writes quota, credentials or counters, even if a peer renewal
	// commits between the read above and the serialized metadata transaction.
	if updated.TotalGB == before.TotalGB && updated.ExpiryTime == before.ExpiryTime && updated.Enable == before.Enable {
		return true, result, applyMeshClientMetadata(db, existing, updated, limitHwid)
	}
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
		if err == nil {
			err = applyMeshClientMetadata(db, existing, updated, limitHwid)
		}
		return true, MeshOperationResult{Operation: receipt.Operation, Pending: receipt.ApplicationPending}, err
	}
	managed, result, err := TryMeshLifecycle(ctx, email, "renew", key, &updated.TotalGB, &expires, MeshAvailability{Disabled: &disabled, Unlimited: &unlimited})
	if err == nil {
		err = applyMeshClientMetadata(db, existing, updated, limitHwid)
	}
	return managed, result, err
}

func applyMeshClientMetadata(db *gorm.DB, original model.ClientRecord, next model.Client, limitHwid int) error {
	if original.Comment == next.Comment && original.Group == next.Group && original.TgID == next.TgID && original.LimitIP == next.LimitIP && original.AdTag == next.AdTag && original.LimitHwid == limitHwid {
		return nil
	}
	return submitTrafficWrite(func() error {
		return db.Transaction(func(tx *gorm.DB) error {
			var current model.ClientRecord
			if err := tx.First(&current, "id = ? AND email = ?", original.Id, original.Email).Error; err != nil {
				return err
			}
			if current.UUID != original.UUID || current.SubID != original.SubID || current.Password != original.Password || current.Auth != original.Auth {
				return errors.New("client identity changed while saving metadata")
			}
			now := time.Now().UnixMilli()
			if err := tx.Model(&current).Updates(map[string]any{"comment": next.Comment, "group_name": next.Group, "tg_id": next.TgID, "limit_ip": next.LimitIP, "limit_hwid": limitHwid, "ad_tag": next.AdTag, "updated_at": now}).Error; err != nil {
				return err
			}
			var inbounds []model.Inbound
			if err := tx.Table("inbounds i").Select("i.*").Joins("JOIN client_inbounds ci ON ci.inbound_id = i.id").Where("ci.client_id = ?", current.Id).Find(&inbounds).Error; err != nil {
				return err
			}
			for _, inbound := range inbounds {
				var body map[string]any
				if err := json.Unmarshal([]byte(inbound.Settings), &body); err != nil {
					return err
				}
				entries, _ := body["clients"].([]any)
				found := false
				for _, entry := range entries {
					row, ok := entry.(map[string]any)
					if !ok || row["email"] != current.Email {
						continue
					}
					found = true
					row["comment"], row["group"], row["tgId"] = next.Comment, next.Group, next.TgID
					row["limitIp"], row["adTag"], row["updated_at"] = next.LimitIP, next.AdTag, now
				}
				if !found {
					return errors.New("client metadata attachment disappeared")
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					return err
				}
				if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).Update("settings", string(encoded)).Error; err != nil {
					return err
				}
				if inbound.NodeID != nil {
					if err := (&NodeService{}).MarkNodeDirtyTx(tx, *inbound.NodeID); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
}

func legacyAbsoluteMeshRequest(p quotaescrow.Policy, limit, expires int64, disabled, unlimited bool) (MeshParentPolicyInput, string) {
	input := MeshParentPolicyInput{Subscription: p.Subscription, ControlEpoch: p.ControlEpoch,
		Epoch: p.Epoch, ExpectedHash: quotaescrow.PolicyHash(p), Kind: "renew",
		Limit: limit, ExpiresAt: expires, Disabled: &disabled, Unlimited: &unlimited}
	encoded, _ := json.Marshal(input)
	h := sha256.Sum256(append([]byte("legacy-absolute-client/v1\x00"), encoded...))
	return input, "legacy-" + hex.EncodeToString(h[:])
}
