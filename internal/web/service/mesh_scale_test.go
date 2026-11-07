package service

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Optional deployment sizing check, using the actual checkpoint/settlement
// implementation with approximately the live master subscription count.
func TestMeshScaleAcceptance(t *testing.T) {
	if os.Getenv("MESH_SCALE_ACCEPTANCE") != "1" {
		t.Skip("explicit scale acceptance not requested")
	}
	setupConflictDB(t)
	db := database.GetDB()
	public, private := map[string][]byte{}, map[string]ed25519.PrivateKey{}
	for _, owner := range []string{"local", "at", "nl", "us"} {
		pub, key, _ := ed25519.GenerateKey(nil)
		public[owner], private[owner] = pub, key
	}
	config := &MeshConfig{Owner: "local", PrivateKey: private["local"], StateDir: t.TempDir()}
	cp, err := OpenMeshCheckpoint(db, config, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	now := time.Now().Unix()
	if err := db.Transaction(func(tx *gorm.DB) error {
		for i := 0; i < 1400; i++ {
			sub, email := fmt.Sprintf("scale-%04d", i), fmt.Sprintf("device-%04d", i)
			p := quotaescrow.Policy{Mode: "shared", Subscription: sub, Epoch: "one", Limit: 10000, ExpiresAt: now + 3600, Keys: public, Grants: map[string]int64{"local": 0, "at": 0, "nl": 0, "us": 0}}
			if err := ActivateMeshMeters(tx, p, "local", []string{email}); err != nil {
				return err
			}
			for _, owner := range []string{"at", "nl", "us"} {
				if err := quotaescrow.NewStore(tx).Observe(sub, owner, private[owner], 20, now); err != nil {
					return err
				}
			}
			if err := recordMeshLocalUsage(tx, email, 100, 0); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	failures, err := SettleMeshMeters(db, func(string) (ed25519.PrivateKey, error) { return private["local"], nil })
	if err != nil || len(failures) != 0 {
		t.Fatal("settlement failed", len(failures), err)
	}
	t.Logf("1400 subscriptions / four members: changed settlement %s", time.Since(start))
	start = time.Now()
	if err := cp.Advance(db); err != nil {
		t.Fatal(err)
	}
	t.Logf("first full checkpoint %s", time.Since(start))
	start = time.Now()
	if err := cp.Advance(db); err != nil {
		t.Fatal(err)
	}
	t.Logf("unchanged full checkpoint %s", time.Since(start))
	start = time.Now()
	if err := cp.Advance(db); err != nil {
		t.Fatal(err)
	}
	t.Logf("steady unchanged full checkpoint %s", time.Since(start))
	start = time.Now()
	if err := cp.AdvanceSubscription(db, "scale-0001"); err != nil {
		t.Fatal(err)
	}
	t.Logf("single subscription publication checkpoint %s", time.Since(start))
}
