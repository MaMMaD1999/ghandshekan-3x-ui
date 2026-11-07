package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

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
