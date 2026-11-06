package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshAdmissionBlocksAllAliasesWithoutChangingStoredClients(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := quotaescrow.Policy{Subscription: "subscription", Epoch: "epoch", Limit: 100, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{"owner": 100}, Keys: map[string][]byte{"owner": pub}}
	store := quotaescrow.NewStore(db)
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	if err := quotaescrow.InitializeClock(db, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"phone", "laptop"} {
		if err := db.Create(&model.MeshBinding{Email: email, Subscription: p.Subscription, Owner: "owner"}).Error; err != nil {
			t.Fatal(err)
		}
		if allowed, err := MeshClientAllowed(email); err != nil || !allowed {
			t.Fatal(email, allowed, err)
		}
	}
	if err := store.Observe(p.Subscription, "owner", key, 100, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"phone", "laptop"} {
		if allowed, err := MeshClientAllowed(email); err != nil || allowed {
			t.Fatal(email, allowed, err)
		}
	}
	if allowed, err := MeshClientAllowed("legacy"); err != nil || !allowed {
		t.Fatal("legacy behavior changed", allowed, err)
	}
	inbound := &model.Inbound{Protocol: model.VLESS, Enable: true, Settings: `{"clients":[{"email":"phone","id":"a"},{"email":"legacy","id":"b"},{"email":"laptop","id":"c"}],"decryption":"none"}`}
	original := inbound.Settings
	filtered, err := FilterMeshInbound(inbound)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(filtered.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	clients := settings["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["email"] != "legacy" {
		t.Fatal(settings)
	}
	if inbound.Settings != original || !inbound.Enable || settings["decryption"] != "none" {
		t.Fatal("stored inbound modified")
	}
}

func TestMeshAdmissionMissingPolicyFailsClosedOnlyForEnrolledClient(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	if err := db.Create(&model.MeshBinding{Email: "enrolled", Subscription: "missing", Owner: "owner"}).Error; err != nil {
		t.Fatal(err)
	}
	blocked, err := MeshBlockedEmails(db, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if !blocked["enrolled"] || blocked["legacy"] {
		t.Fatal(blocked)
	}
}
