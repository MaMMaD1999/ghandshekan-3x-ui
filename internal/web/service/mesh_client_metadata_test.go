package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestMeshMetadataEditPreservesRenewedQuotaAndUsage(t *testing.T) {
	db, inbound, client := legacyGuardFixture(t)
	var before model.ClientRecord
	if err := db.First(&before, "email = ?", client.Email).Error; err != nil {
		t.Fatal(err)
	}
	next := *before.ToClient()
	next.Comment, next.Group, next.TgID, next.LimitIP = "new note", "new group", 456, 2
	// A concurrent certified renewal must not be overwritten by this old form.
	if err := db.Model(&before).Update("total_gb", int64(5000)).Error; err != nil {
		t.Fatal(err)
	}
	if err := applyMeshClientMetadata(db, before, next, 3); err != nil {
		t.Fatal(err)
	}
	var after model.ClientRecord
	if err := db.First(&after, "email = ?", client.Email).Error; err != nil {
		t.Fatal(err)
	}
	if after.TotalGB != 5000 || after.UUID != before.UUID || after.Comment != next.Comment || after.Group != next.Group || after.LimitHwid != 3 {
		t.Fatal("metadata changed financial/identity state or was not saved")
	}
	var usage xray.ClientTraffic
	if err := db.First(&usage, "email = ?", client.Email).Error; err != nil {
		t.Fatal(err)
	}
	if usage.Up != 600 || usage.Down != 400 {
		t.Fatal("metadata changed usage")
	}
	var stored model.Inbound
	if err := db.First(&stored, inbound.Id).Error; err != nil {
		t.Fatal(err)
	}
	if err := requireMeshSettingsUnchanged(db, inbound.Settings, stored.Settings); err != nil {
		t.Fatal("metadata cannot synchronize to a peer", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(stored.Settings), &body); err != nil {
		t.Fatal(err)
	}
	row := body["clients"].([]any)[0].(map[string]any)
	row["id"] = "rotated-without-authorization"
	b, _ := json.Marshal(body)
	if err := requireMeshSettingsUnchanged(db, stored.Settings, string(b)); err == nil {
		t.Fatal("metadata allowance bypassed credential guard")
	}
}

func TestMeshMetadataOnlyDoesNotRequireOrIssueRenewal(t *testing.T) {
	db, _, client := legacyGuardFixture(t)
	var record model.ClientRecord
	if err := db.First(&record, "email = ?", client.Email).Error; err != nil {
		t.Fatal(err)
	}
	next := *record.ToClient()
	next.Comment = "saved without a quota operation"
	managed, result, err := TryMeshClientEdit(context.Background(), client.Email, next, 0, "metadata-only")
	if err != nil || !managed || result.Operation != "" {
		t.Fatal(managed, result, err)
	}
	next.ID = "different-credential"
	if _, _, err := TryMeshClientEdit(context.Background(), client.Email, next, 0, "credential-change"); err == nil {
		t.Fatal("uncoordinated credential change accepted")
	}
}
