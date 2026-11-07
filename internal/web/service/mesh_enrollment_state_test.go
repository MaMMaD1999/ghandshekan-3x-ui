package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func TestNativeEnrollmentReloadPinsRegistry(t *testing.T) {
	a, _ := enrollmentAdminFixture(t)
	path, c := meshRuntimeFixture(t, "manager")
	c.Authority = a.manager.Coordinator.Authority.Public().(ed25519.PublicKey)
	c.ControlEpoch = "reload-test"
	c.PeerKeys = map[string][]byte{c.Owner: ed25519.PrivateKey(c.PrivateKey).Public().(ed25519.PublicKey)}
	for _, owner := range []string{"second", "third"} {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		c.PeerKeys[owner], c.Peers[owner] = pub, c.Peers[c.Owner]
	}
	c.EnrollmentAuthorityFile = filepath.Join(filepath.Dir(path), "authority.json")
	c.EnrollmentJournalFile = filepath.Join(filepath.Dir(path), "enrollment.sqlite")
	c.NativeEnrollment, c.NativeEnrollmentExclude = true, []string{"protected"}
	a.nativeConfigPath = path
	a.manager.Coordinator.ControlEpoch, a.manager.Coordinator.ControlKeys = c.ControlEpoch, c.PeerKeys
	write := func() {
		body, _ := json.Marshal(c)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := a.reloadNativeEnrollment(); err != nil || !a.nativeEnabled || len(a.nativeExclude) != 1 {
		t.Fatal(err)
	}
	c.ControlEpoch = "changed-membership"
	write()
	if err := a.reloadNativeEnrollment(); err == nil || a.nativeEnabled {
		t.Fatal("live membership change was accepted")
	}
}

func TestEnrollmentGuardRejectsEditAfterPreflightBeforeBarrier(t *testing.T) {
	for _, field := range []string{"total_gb", "expiry_time", "enable", "traffic_reset", "traffic_reset_day", "reset", "uuid"} {
		t.Run(field, func(t *testing.T) {
			a, c := enrollmentAdminFixture(t)
			plan, _, err := a.builder.Enrollment(context.Background(), "native-parent", []quotaescrow.LegacyRoot{{Owner: c.Owner, Alias: "phone"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.builder.CheckReady(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			var value any = int64(2000)
			if field == "enable" {
				value = false
			}
			if field == "traffic_reset" {
				value = "daily"
			}
			if field == "uuid" {
				value = "changed-credential"
			}
			if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Update(field, value).Error; err != nil {
				t.Fatal(err)
			}
			c.Drain = func(context.Context, []string) error { t.Fatal("stale enrollment interrupted live client"); return nil }
			if _, err := controlRequest(t, c, a.builder.Authority, plan, "prepare", nil, nil); err == nil {
				t.Fatal("stale settings fenced/overwrote concurrent edit")
			}
			var count int64
			if err := c.DB.Model(&model.MeshControlState{}).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("failed CAS left an admission barrier", count, err)
			}
		})
	}
}

func TestEnrollmentGuardPreservesLiveUsageAndDurableRetry(t *testing.T) {
	a, c := enrollmentAdminFixture(t)
	plan, _, err := a.builder.Enrollment(context.Background(), "native-parent", []quotaescrow.LegacyRoot{{Owner: c.Owner, Alias: "phone"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DB.Transaction(func(tx *gorm.DB) error {
		if err := recordMeshLocalUsage(tx, "phone", 17, 0); err != nil {
			return err
		}
		return tx.Model(&xray.ClientTraffic{}).Where("email = ?", "phone").Update("up", gorm.Expr("up + 17")).Error
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.builder.CheckReady(context.Background(), plan); err != nil {
		t.Fatal("ordinary traffic invalidated state guard", err)
	}
	r, err := controlRequest(t, c, a.builder.Authority, plan, "prepare", nil, nil)
	if err != nil || r.Local["phone"] != 917 || r.Historical.Aliases["phone"].Total.Up != 67 {
		t.Fatal("lost in-flight usage", r, err)
	}
	replay, err := controlRequest(t, c, a.builder.Authority, plan, "prepare", nil, nil)
	if err != nil || replay.Local["phone"] != r.Local["phone"] {
		t.Fatal("retry rebased usage", err)
	}
	if err := quotaescrow.VerifyControlReceipt(replay, plan, c.Key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestNativeEnrollmentUsesPanelPolicyAndRetriesOriginalIntent(t *testing.T) {
	a, c := enrollmentAdminFixture(t)
	expiry := int64(2000000000123)
	if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Updates(map[string]any{"total_gb": 12345, "expiry_time": expiry}).Error; err != nil {
		t.Fatal(err)
	}
	first, err := a.QueueNative(context.Background(), "phone", "native-one")
	if err != nil || first.Pending {
		t.Fatal(first, err)
	}
	var binding model.MeshBinding
	if err := c.DB.First(&binding, "email = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	l, err := quotaescrow.NewStore(c.DB).Load(binding.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	p := l.Policy()
	if p.Limit != 12345 || p.ExpiresAt != 2000000001 || p.Unlimited || p.Disabled {
		t.Fatal("native subscription policy changed", p)
	}
	if n, err := l.Billed(); err != nil || n != 100 {
		t.Fatal("history changed", n, err)
	}
	// Model a later accepted renewal: request retry must recover the saved
	// enrollment target, not attempt another enrollment with new numbers.
	if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Update("total_gb", 54321).Error; err != nil {
		t.Fatal(err)
	}
	replayed, err := a.QueueNative(context.Background(), "phone", "native-one")
	if err != nil || replayed.Pending || replayed.Operation != first.Operation {
		t.Fatal("retry changed original intent", replayed, err)
	}
}

func TestNativeEnrollmentRefusesUnsupportedInitialStateWithoutWrites(t *testing.T) {
	for _, change := range []map[string]any{{"expiry_time": -500}, {"reset": 30}, {"reset_day": 5}, {"reset_weekday": 1}, {"reset_max": 1}} {
		a, c := enrollmentAdminFixture(t)
		if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Updates(change).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := a.QueueNative(context.Background(), "phone", "native"); err == nil {
			t.Fatal("unsupported state silently changed", change)
		}
		for _, table := range []any{&quotaescrow.ControlJob{}, &model.MeshControlState{}, &model.MeshBinding{}} {
			var count int64
			if err := c.DB.Model(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("rejected native enrollment wrote state", count, err)
			}
		}
	}
}

func TestAutomaticNativeEnrollmentSkipsAppProtectedAndInactiveFirstUse(t *testing.T) {
	a, c := enrollmentAdminFixture(t)
	if err := c.DB.AutoMigrate(&model.MeshBinding{}); err != nil {
		t.Fatal(err)
	}
	row, err := a.nextNativeEnrollment(0)
	if err != nil || row == nil || row.Email != "phone" {
		t.Fatal(row, err)
	}
	a.nativeExclude = []string{"phone"}
	if row, err := a.nextNativeEnrollment(0); err != nil || row != nil {
		t.Fatal("protected client selected", row, err)
	}
	a.nativeExclude = nil
	for _, change := range []map[string]any{{"comment": "GhandShekan application device"}, {"expiry_time": -100}, {"reset": 30}} {
		if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Updates(change).Error; err != nil {
			t.Fatal(err)
		}
		if row, err := a.nextNativeEnrollment(0); err != nil || row != nil {
			t.Fatal("ineligible client selected", row, err)
		}
		if err := c.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Updates(map[string]any{"comment": "", "expiry_time": 0, "reset": 0}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.QueueNative(context.Background(), "phone", "native-automatic-v1"); err != nil {
		t.Fatal(err)
	}
	if row, err := a.nextNativeEnrollment(0); err != nil || row != nil {
		t.Fatal("already enrolled client selected", row, err)
	}
}
