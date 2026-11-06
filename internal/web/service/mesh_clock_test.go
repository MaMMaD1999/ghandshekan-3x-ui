package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshClockFaultFencesEnrolledUsersOnly(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := quotaescrow.Policy{Subscription: "shared", Epoch: "first", Limit: 100, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{"local": 100}, Keys: map[string][]byte{"local": pub}}
	if err := ActivateMeshMeters(db, p, "local", []string{"phone", "laptop"}); err != nil {
		t.Fatal(err)
	}
	if blocked, err := MeshBlockedEmailsNow(db); err != nil || len(blocked) != 0 {
		t.Fatal(blocked, err)
	}
	if err := db.Where("id = ?", "local").Delete(&quotaescrow.ClockState{}).Error; err != nil {
		t.Fatal(err)
	}
	blocked, err := MeshBlockedEmailsNow(db)
	if err != nil || !blocked["phone"] || !blocked["laptop"] || len(blocked) != 2 {
		t.Fatal(blocked, err)
	}
	if allowed, err := MeshClientAllowed("phone"); err != nil || allowed {
		t.Fatal(allowed, err)
	}
	if allowed, err := MeshClientAllowed("ordinary"); err != nil || !allowed {
		t.Fatal(allowed, err)
	}
}
