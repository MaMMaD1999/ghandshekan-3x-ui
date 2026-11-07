package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func checkpointFixture(t *testing.T) (*gorm.DB, *MeshConfig, *MeshCheckpoint, quotaescrow.Policy) {
	t.Helper()
	setupConflictDB(t)
	db := database.GetDB()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := &MeshConfig{Owner: "local", PrivateKey: key, StateDir: t.TempDir()}
	cp, err := OpenMeshCheckpoint(db, c, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	// A subscription named like metadata must not overwrite checkpoint identity.
	p := quotaescrow.Policy{Subscription: "identity", Epoch: "one", Limit: 10000, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{"local": 10000}, Keys: map[string][]byte{"local": pub}}
	if err := ActivateMeshMeters(db, p, "local", []string{"phone"}); err != nil {
		t.Fatal(err)
	}
	if err := cp.Advance(db); err != nil {
		t.Fatal(err)
	}
	return db, c, cp, p
}

func TestMeshCheckpointDetectsRestoreAndKeepsIdentityNamespace(t *testing.T) {
	db, c, cp, p := checkpointFixture(t)
	var before quotaescrow.Record
	if err := db.First(&before, "subscription = ?", p.Subscription).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 10, 20) }); err != nil {
		t.Fatal(err)
	}
	failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return c.PrivateKey, nil })
	if err != nil || len(failures) > 0 {
		t.Fatal(failures, err)
	}
	if err := cp.Advance(db); err != nil {
		t.Fatal(err)
	}
	other, err := OpenMeshCheckpoint(db, c, false)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	if err := db.Save(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := cp.Advance(db); !errors.Is(err, ErrMeshRestore) {
		t.Fatal("old ledger admitted", err)
	}
	if other, err := OpenMeshCheckpoint(db, c, false); err == nil {
		other.Close()
		t.Fatal("restored ledger admitted after restart")
	}
}

func TestMeshScopedCheckpointRejectsRollbackBeforePublication(t *testing.T) {
	db, c, cp, p := checkpointFixture(t)
	var before quotaescrow.Record
	if err := db.First(&before, "subscription = ?", p.Subscription).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 20, 30) }); err != nil {
		t.Fatal(err)
	}
	failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return c.PrivateKey, nil })
	if err != nil || len(failures) > 0 {
		t.Fatal(failures, err)
	}
	if err := cp.AdvanceSubscription(db, p.Subscription); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := cp.AdvanceSubscription(db, p.Subscription); !errors.Is(err, ErrMeshRestore) {
		t.Fatal("scoped publication accepted rollback", err)
	}
}

func TestMeshCheckpointRejectsMissingBindingMeterClockAndTampering(t *testing.T) {
	for _, kind := range []string{"binding", "meter", "clock", "signature", "floor-signature", "same-revision-rows", "same-revision-policy", "higher-revision", "watermark"} {
		t.Run(kind, func(t *testing.T) {
			db, c, cp, p := checkpointFixture(t)
			if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 100, 0) }); err != nil {
				t.Fatal(err)
			}
			failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return c.PrivateKey, nil })
			if err != nil || len(failures) > 0 {
				t.Fatal(failures, err)
			}
			if err := cp.Advance(db); err != nil {
				t.Fatal(err)
			}
			// Warm exact-value caches; they must never hide a changed DB value.
			for i := 0; i < 2; i++ {
				if err := cp.Advance(db); err != nil {
					t.Fatal(err)
				}
			}
			var mutate error
			switch kind {
			case "binding":
				mutate = db.Where("email = ?", "phone").Delete(&model.MeshBinding{}).Error
			case "meter":
				mutate = db.Where("email = ?", "phone").Delete(&model.LocalUsage{}).Error
			case "clock":
				mutate = db.Model(&quotaescrow.ClockState{}).Where("id = ?", "local").Update("last_unix", 1).Error
			case "signature":
				mutate = cp.db.Model(&meshCheckpointEntry{}).Where("id = ?", "sub:"+p.Subscription).Update("body", []byte("{}")).Error
			case "floor-signature":
				mutate = cp.db.Model(&meshCheckpointEntry{}).Where("id = ?", "sub:"+p.Subscription).Update("signature", make([]byte, ed25519.SignatureSize)).Error
			case "same-revision-rows":
				mutate = db.Model(&quotaescrow.Record{}).Where("subscription = ?", p.Subscription).Update("rows_json", "[]").Error
			case "same-revision-policy":
				mutate = db.Model(&quotaescrow.Record{}).Where("subscription = ?", p.Subscription).Update("policy_json", "{}").Error
			case "higher-revision":
				mutate = db.Model(&quotaescrow.Record{}).Where("subscription = ?", p.Subscription).Updates(map[string]any{"revision": 99, "rows_json": "[]"}).Error
			case "watermark":
				mutate = db.Model(&quotaescrow.Meter{}).Where("subscription = ?", p.Subscription).Update("watermark", 0).Error
			}
			if mutate != nil {
				t.Fatal(mutate)
			}
			if err := cp.Advance(db); !errors.Is(err, ErrMeshRestore) {
				t.Fatal("rollback accepted", kind, err)
			}
		})
	}
}

func TestMeshCheckpointMissingFileCannotBlessExistingLedger(t *testing.T) {
	db, _, _, _ := checkpointFixture(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := &MeshConfig{Owner: "local", PrivateKey: key, StateDir: filepath.Join(t.TempDir(), "fresh")}
	if cp, err := OpenMeshCheckpoint(db, c, false); err == nil {
		cp.Close()
		t.Fatal("lost checkpoint recreated")
	}
	if _, err := os.Stat(c.StateDir); !os.IsNotExist(err) {
		t.Fatal("failed check created state", err)
	}
}

func TestMeshCheckpointColdStartRejectsBackupFromBeforeEnrollment(t *testing.T) {
	db, c, cp, _ := checkpointFixture(t)
	if err := db.Exec("DELETE FROM mesh_client_bindings").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM quota_escrow_states").Error; err != nil {
		t.Fatal(err)
	}
	if err := cp.Advance(db); !errors.Is(err, ErrMeshRestore) {
		t.Fatal("pre-enrollment restore accepted", err)
	}
	if other, err := OpenMeshCheckpoint(db, c, false); err == nil {
		other.Close()
		t.Fatal("cold start accepted lost enrollment")
	}
}

func TestMeshCheckpointAcceptsProvenResetAndRenewalWithoutRebilling(t *testing.T) {
	for _, kind := range []string{"reset", "renew"} {
		t.Run(kind, func(t *testing.T) {
			db, c, cp, p := checkpointFixture(t)
			db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 100, 0) })
			failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return c.PrivateKey, nil })
			if err != nil || len(failures) > 0 {
				t.Fatal(failures, err)
			}
			if err := cp.Advance(db); err != nil {
				t.Fatal(err)
			}
			store := quotaescrow.NewStore(db)
			if err := store.BeginTransition(p.Subscription, "two", "operation"); err != nil {
				t.Fatal(err)
			}
			proof, err := store.Freeze(p.Subscription, c.Owner, "two", "operation", c.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := cp.Advance(db); err != nil {
				t.Fatal(err)
			}
			next := p
			next.Epoch = "two"
			next.Limit = 20000
			next.Grants = map[string]int64{c.Owner: 19000}
			if kind == "renew" {
				next.AlreadyBilled = 100
			}
			var local model.LocalUsage
			db.First(&local, "email = ?", "phone")
			if err := store.CommitTransition(next, kind, []quotaescrow.FreezeProof{proof}, []quotaescrow.Meter{{Subscription: p.Subscription, Owner: c.Owner, Source: local.Source, Epoch: next.Epoch, Watermark: local.Billed}}); err != nil {
				t.Fatal(err)
			}
			if err := cp.Advance(db); err != nil {
				t.Fatal(err)
			}
			failures, err = SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return c.PrivateKey, nil })
			if err != nil || len(failures) > 0 {
				t.Fatal(failures, err)
			}
			ledger, err := store.Load(p.Subscription)
			if err != nil {
				t.Fatal(err)
			}
			billed, err := ledger.Billed()
			if err != nil || billed != next.AlreadyBilled {
				t.Fatal("rebilled transition", billed, err)
			}
		})
	}
}
