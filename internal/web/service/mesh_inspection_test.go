package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshInspectionSeparatesMembershipEpochFromResetCycle(t *testing.T) {
	c, p, keys := membershipFixture(t)
	u, err := quotaescrow.DraftPolicyChange(p, "reset-for-inspection", "reset", quotaescrow.ControlTarget{Limit: p.Limit})
	if err != nil {
		t.Fatal(err)
	}
	u.Votes = map[string][]byte{}
	for _, owner := range []string{"a", "b"} {
		u.Votes[owner] = quotaescrow.PolicyUpdateVote(u, keys[owner])
	}
	if err := c.ApplySharedUpdates(context.Background(), p.Subscription, []quotaescrow.PolicyUpdate{u}); err != nil {
		t.Fatal(err)
	}
	pub, authority, _ := ed25519.GenerateKey(rand.Reader)
	c.Authority = pub // A separate authenticated read-only inventory caller.
	now := time.Now().Unix()
	request := quotaescrow.Inspection{Owner: c.Owner, Nonce: rand.Text(), Emails: []string{"phone"}, IssuedAt: now - 1, ValidUntil: now + 60}
	signed, _ := quotaescrow.SignInspection(request, authority)
	result, err := c.Inspect(signed)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := meshReportScopes(c.DB)
	if err != nil || scopes["phone"].Epoch != p.Epoch+"/cycle/2" || result.Aliases[0].Epoch != p.Epoch {
		t.Fatal("billing generation contaminated device membership identity", result, scopes, err)
	}
	if err := quotaescrow.VerifyInventory(result, request, c.Key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestMeshInspectionAuthenticatesAuthorityAndInventory(t *testing.T) {
	c, secret, plan, _ := controlFixture(t)
	now := time.Now().Unix()
	request := quotaescrow.Inspection{Owner: c.Owner, Nonce: rand.Text(), Emails: []string{"phone"}, IssuedAt: now - 1, ValidUntil: now + 60}
	signed, err := quotaescrow.SignInspection(request, secret)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Inspect(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := quotaescrow.VerifyInventory(result, request, c.Key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if len(result.Aliases) != 1 || result.Aliases[0].Claim != plan.Claims[c.Owner][0] || !result.Aliases[0].Local {
		t.Fatal("wrong ownership inventory", result)
	}
	body, _ := json.Marshal(result)
	if strings.Contains(string(body), "credential") || strings.Contains(string(body), "password") {
		t.Fatal("inventory exposed a credential")
	}
	if _, err := c.Inspect(quotaescrow.SignedInspection{Request: request, Signature: make([]byte, 64)}); err == nil {
		t.Fatal("unsigned inspection accepted")
	}
	changed := request
	changed.Nonce = rand.Text()
	if quotaescrow.VerifyInventory(result, changed, c.Key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("inventory replay matched another request")
	}
	result.Aliases[0].Limit++
	if quotaescrow.VerifyInventory(result, request, c.Key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("inventory tampering accepted")
	}
}
