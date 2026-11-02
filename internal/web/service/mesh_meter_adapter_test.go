package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func TestMeshMeterActivationSettlementAndRetry(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	p := quotaescrow.Policy{Subscription: "shared", Epoch: "first", Limit: 1000, AlreadyBilled: 300, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{"local": 700}, Keys: map[string][]byte{"local": pub}}
	if err := db.Create(&model.LocalUsage{Email: "phone", Source: "stable-phone", Billed: 9000}).Error; err != nil {
		t.Fatal(err)
	}
	if err := ActivateMeshMeters(db, p, "local", []string{"phone", "laptop"}); err != nil {
		t.Fatal(err)
	}
	store := quotaescrow.NewStore(db)
	assertBilled := func(want int64) {
		t.Helper()
		l, err := store.Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.Billed()
		if err != nil || got != want {
			t.Fatalf("billed=%d want=%d err=%v", got, want, err)
		}
	}
	assertBilled(300)
	tick := func(email string, n int64) {
		t.Helper()
		if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, email, n, 0) }); err != nil {
			t.Fatal(err)
		}
	}
	tick("phone", 40)
	tick("laptop", 60)
	settle := func() {
		t.Helper()
		failures, err := SettleMeshMeters(db, func(owner string) (ed25519.PrivateKey, error) {
			if owner != "local" {
				t.Fatal(owner)
			}
			return key, nil
		})
		if err != nil || len(failures) != 0 {
			t.Fatal(failures, err)
		}
	}
	settle()
	assertBilled(400)
	settle()
	assertBilled(400)
	// A failed later alias must roll back earlier aliases of this subscription.
	tick("phone", 10)
	tick("laptop", 20)
	if err := db.Exec("CREATE TRIGGER fail_mesh_settlement BEFORE UPDATE ON quota_escrow_meters WHEN NEW.source = 'stable-phone' BEGIN SELECT RAISE(ABORT, 'disk error'); END;").Error; err != nil {
		t.Fatal(err)
	}
	failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return key, nil })
	if err != nil || failures[p.Subscription] == nil {
		t.Fatal(failures, err)
	}
	assertBilled(400)
	if err := db.Exec("DROP TRIGGER fail_mesh_settlement").Error; err != nil {
		t.Fatal(err)
	}
	settle()
	assertBilled(430)
	tick("phone", 570)
	settle()
	assertBilled(1000)
	blocked, err := MeshBlockedEmails(db, time.Now().Unix())
	if err != nil || !blocked["phone"] || !blocked["laptop"] {
		t.Fatal(blocked, err)
	}
	// Repeating enrollment must not reset watermarks or consumption.
	if err := ActivateMeshMeters(db, p, "local", []string{"phone", "laptop"}); err == nil {
		t.Fatal("re-enrollment overwrote epoch")
	}
	settle()
	assertBilled(1000)
}

func TestMeshAliasCannotJoinTwoPolicies(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := quotaescrow.Policy{Subscription: "one", Epoch: "first", Limit: 100, Grants: map[string]int64{"local": 100}, Keys: map[string][]byte{"local": pub}}
	if err := ActivateMeshMeters(db, p, "local", []string{"same"}); err != nil {
		t.Fatal(err)
	}
	p.Subscription = "two"
	if err := ActivateMeshMeters(db, p, "local", []string{"new-alias", "same"}); err == nil {
		t.Fatal("rebound existing alias")
	}
	var n int64
	for _, m := range []any{&quotaescrow.Record{}, &quotaescrow.Meter{}, &model.MeshBinding{}} {
		if err := db.Model(m).Where("subscription = ?", "two").Count(&n).Error; err != nil || n != 0 {
			t.Fatal("partial enrollment", n, err)
		}
	}
	if err := db.Model(&model.LocalUsage{}).Where("email = ?", "new-alias").Count(&n).Error; err != nil || n != 0 {
		t.Fatal("baseline escaped rollback", n, err)
	}
}
