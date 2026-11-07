package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func membershipFixture(t *testing.T) (*MeshControl, quotaescrow.Policy, map[string]ed25519.PrivateKey) {
	t.Helper()
	c, authority, plan, _ := controlFixture(t, "a")
	keys := map[string]ed25519.PrivateKey{"a": c.Key}
	public := map[string][]byte{"a": c.Key.Public().(ed25519.PublicKey)}
	for _, id := range []string{"b", "c"} {
		pub, key, _ := ed25519.GenerateKey(nil)
		keys[id] = key
		public[id] = pub
	}
	p := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Mode: "shared", Limit: 1000, AlreadyBilled: 100,
		Version: 1, ResetGeneration: 1, Manager: "a", Authority: authority.Public().(ed25519.PublicKey), Keys: public,
		Grants: map[string]int64{"a": 0, "b": 0, "c": 0}, ControlEpoch: "cluster", ControlKeys: public,
		Aliases: quotaescrow.AliasCatalog{"a": {"phone": {Fingerprint: plan.Claims["a"][0].Fingerprint, Revision: 1}}}}
	if err := ActivateMeshMeters(c.DB, p, "a", []string{"phone"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	c.Enforcer.Fence = func(_ context.Context, emails []string) error {
		pending, err := meshPendingAliases(c.DB)
		if err != nil {
			return err
		}
		for _, email := range emails {
			if !pending[email] {
				t.Fatal("fence before durable alias barrier", email)
			}
		}
		return nil
	}
	return c, p, keys
}

func provisionMembershipAlias(t *testing.T, c *MeshControl, email string, enabled bool) string {
	t.Helper()
	client := model.ClientRecord{Email: email, UUID: "credential-" + email, SubID: "subscription", Enable: enabled}
	if err := c.DB.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	// GORM applies the model's true default to a zero-value bool on Create;
	// production provisioning persists an explicit false separately as well.
	if err := c.DB.Model(&client).Update("enable", enabled).Error; err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"clients": []any{map[string]any{"email": email, "id": client.UUID, "enable": enabled}}})
	inbound := model.Inbound{Tag: email, Port: 12346, Protocol: "vless", Settings: string(raw), Enable: true}
	if err := c.DB.Create(&inbound).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.DB.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatal(err)
	}
	fp, err := MeshAliasFingerprint(c.DB, email)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func signedAlias(t *testing.T, p quotaescrow.Policy, id string, patch quotaescrow.AliasPatch, keys map[string]ed25519.PrivateKey) quotaescrow.PolicyUpdate {
	t.Helper()
	u, err := quotaescrow.DraftAliasChange(p, id, patch)
	if err != nil {
		t.Fatal(err)
	}
	u.Votes = map[string][]byte{}
	for _, owner := range []string{"a", "b"} {
		u.Votes[owner] = quotaescrow.PolicyUpdateVote(u, keys[owner])
	}
	return u
}

func TestMeshAttachRevokeRenewRetryPreservesUsageAndOtherDevice(t *testing.T) {
	c, p, keys := membershipFixture(t)
	fp := provisionMembershipAlias(t, c, "tablet", false)
	add := signedAlias(t, p, "add-tablet", quotaescrow.AliasPatch{Owner: "a", Email: "tablet", Fingerprint: fp}, keys)
	drained := false
	c.Drain = func(_ context.Context, emails []string) error {
		if !reflect.DeepEqual(map[string]bool{"phone": true, "tablet": true}, func() map[string]bool {
			v := map[string]bool{}
			for _, x := range emails {
				v[x] = true
			}
			return v
		}()) {
			t.Fatal("missing alias drain", emails)
		}
		drained = true
		return nil
	}
	if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{add}); err != nil {
		t.Fatal(err)
	}
	if !drained {
		t.Fatal("alias enabled without draining")
	}
	if err := c.DB.Transaction(func(tx *gorm.DB) error {
		if err := recordMeshLocalUsage(tx, "phone", 17, 0); err != nil {
			return err
		}
		return recordMeshLocalUsage(tx, "tablet", 23, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if failures, err := SettleMeshMeters(c.DB, func(string) (ed25519.PrivateKey, error) { return c.Key, nil }); err != nil || len(failures) > 0 {
		t.Fatal(failures, err)
	}
	l, err := quotaescrow.NewStore(c.DB).Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if billed, _ := l.Billed(); billed != 140 {
		t.Fatal("attach duplicated baseline", billed)
	}
	var before []quotaescrow.Meter
	if err := c.DB.Order("source").Find(&before).Error; err != nil {
		t.Fatal(err)
	}
	revoke := signedAlias(t, add.Next, "revoke-tablet", quotaescrow.AliasPatch{Owner: "a", Email: "tablet", Fingerprint: fp, ExpectedRevision: 1, Revoked: true}, keys)
	for i := 0; i < 2; i++ {
		if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{revoke}); err != nil {
			t.Fatal(err)
		}
	}
	blocked, err := MeshBlockedEmails(c.DB, time.Now().Unix())
	if err != nil || !blocked["tablet"] || blocked["phone"] {
		t.Fatal("wrong device was revoked", blocked, err)
	}
	renew, err := quotaescrow.DraftPolicyChange(revoke.Next, "renew-after-revoke", "renew", quotaescrow.ControlTarget{Limit: 2000})
	if err != nil {
		t.Fatal(err)
	}
	renew.Votes = map[string][]byte{}
	for _, owner := range []string{"a", "b"} {
		renew.Votes[owner] = quotaescrow.PolicyUpdateVote(renew, keys[owner])
	}
	if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{renew}); err != nil {
		t.Fatal(err)
	}
	blocked, err = MeshBlockedEmails(c.DB, time.Now().Unix())
	if err != nil || !blocked["tablet"] || blocked["phone"] {
		t.Fatal("renewal revived revoked device", blocked, err)
	}
	var after []quotaescrow.Meter
	if err := c.DB.Order("source").Find(&after).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("membership changed lifetime baselines")
	}
	l, _ = quotaescrow.NewStore(c.DB).Load(p.Subscription)
	if billed, _ := l.Billed(); billed != 140 {
		t.Fatal("revocation/renewal lost consumption", billed)
	}
	if err := c.DB.Model(&model.MeshBinding{}).Where("email = ?", "tablet").Update("authorization_revision", 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.Checkpoint(); !errors.Is(err, ErrMeshRestore) {
		t.Fatal("old device authorization survived rollback", err)
	}
}

func TestMeshAttachRejectsHistoricalOrEnabledAliasWithoutLosingQuota(t *testing.T) {
	for _, kind := range []string{"enabled", "historical", "other-parent", "fingerprint"} {
		t.Run(kind, func(t *testing.T) {
			c, p, keys := membershipFixture(t)
			fp := provisionMembershipAlias(t, c, "tablet", kind == "enabled")
			if kind == "historical" {
				if err := recordMeshLocalUsage(c.DB, "tablet", 5, 0); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "other-parent" {
				if err := c.DB.Create(&model.MeshBinding{Email: "tablet", Owner: "a", Subscription: "someone-else"}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if kind == "fingerprint" {
				fp = strings.Repeat("ab", 32)
			}
			u := signedAlias(t, p, "add-tablet", quotaescrow.AliasPatch{Owner: "a", Email: "tablet", Fingerprint: fp}, keys)
			if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{u}); err == nil {
				t.Fatal("unsafe alias accepted")
			}
			l, err := quotaescrow.NewStore(c.DB).Load(p.Subscription)
			if err != nil {
				t.Fatal(err)
			}
			if l.Policy().Version != 1 {
				t.Fatal("failed attachment partially committed")
			}
			if billed, _ := l.Billed(); billed != 100 {
				t.Fatal("failed attachment changed usage", billed)
			}
		})
	}
}
