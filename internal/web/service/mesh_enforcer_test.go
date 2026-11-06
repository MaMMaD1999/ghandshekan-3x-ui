package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func TestMeshEnforcerIsolatesSettlementFailuresAndRetries(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, email := range []string{"a", "b"} {
		p := quotaescrow.Policy{Subscription: email, Epoch: "one", Limit: 100, ExpiresAt: 200, Grants: map[string]int64{email: 100}, Keys: map[string][]byte{email: pub}}
		if err := ActivateMeshMeters(db, p, email, []string{email}); err != nil {
			t.Fatal(err)
		}
	}
	broken := false
	var denied []string
	e := MeshEnforcer{DB: db, KeyForOwner: func(owner string) (ed25519.PrivateKey, error) {
		if broken && owner == "a" {
			return nil, errors.New("key unavailable")
		}
		return key, nil
	}, Fence: func(_ context.Context, emails []string) error { denied = slices.Clone(emails); return nil }}
	ctx := context.Background()
	if err := e.Reconcile(ctx, 100); err != nil || len(denied) != 0 {
		t.Fatal(err, denied)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "a", 30, 20) }); err != nil {
		t.Fatal(err)
	}
	broken = true
	if err := e.Reconcile(ctx, 100); err == nil || !slices.Equal(denied, []string{"a"}) {
		t.Fatal(err, denied)
	}
	broken = false
	for i := 0; i < 3; i++ {
		if err := e.Reconcile(ctx, 100); err != nil || len(denied) != 0 {
			t.Fatal(err, denied)
		}
	}
	ledger, err := quotaescrow.NewStore(db).Load("a")
	if err != nil {
		t.Fatal(err)
	}
	if billed, err := ledger.Billed(); err != nil || billed != 50 {
		t.Fatal(billed, err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "a", 50, 0) }); err != nil {
		t.Fatal(err)
	}
	if err := e.Reconcile(ctx, 100); err != nil || !slices.Equal(denied, []string{"a"}) {
		t.Fatal(err, denied)
	}
	// A deleted binding cannot silently remove a runtime fence.
	if err := db.Where("email = ?", "a").Delete(&model.MeshBinding{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.Reconcile(ctx, 100); err != nil || !slices.Equal(denied, []string{"a"}) {
		t.Fatal(err, denied)
	}
	// Expiry is enforced locally even without any network activity or traffic.
	if err := e.Reconcile(ctx, 201); err != nil || !slices.Equal(denied, []string{"a", "b"}) {
		t.Fatal(err, denied)
	}
	// An unreadable DB fails closed for all aliases already admitted by this worker.
	if err := db.Migrator().DropTable(&model.MeshBinding{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reconcile(ctx, 201); err == nil || !slices.Equal(denied, []string{"a", "b"}) {
		t.Fatal(err, denied)
	}
}

func TestMeshEnforcerReportsUnconfirmedFence(t *testing.T) {
	setupConflictDB(t)
	sentinel := errors.New("core unavailable")
	e := MeshEnforcer{DB: database.GetDB(), known: map[string]bool{"previously-admitted": true}, KeyForOwner: func(string) (ed25519.PrivateKey, error) { return nil, nil }, Fence: func(context.Context, []string) error { return sentinel }}
	if err := e.Reconcile(context.Background(), 100); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestMeshEnforcerDoesNotClearUnknownFenceOnStartup(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	e := MeshEnforcer{DB: db, Fence: func(context.Context, []string) error { t.Fatal("startup cleared an unknown core fence"); return nil }}
	if err := e.Reconcile(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropTable(&model.MeshBinding{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reconcile(context.Background(), 100); err == nil {
		t.Fatal("missing bindings did not fail closed")
	}
}
