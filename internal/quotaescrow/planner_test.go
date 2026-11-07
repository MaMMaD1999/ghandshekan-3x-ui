package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func plannerFixture(t *testing.T) (PlanBuilder, map[string]map[string]InspectedAlias) {
	t.Helper()
	_, authority, _ := ed25519.GenerateKey(nil)
	keys, private := map[string][]byte{}, map[string]ed25519.PrivateKey{}
	for _, owner := range []string{"master", "node-a", "node-b"} {
		pub, key, _ := ed25519.GenerateKey(nil)
		keys[owner], private[owner] = pub, key
	}
	rows := map[string]map[string]InspectedAlias{}
	for owner := range keys {
		rows[owner] = map[string]InspectedAlias{"device-1": {Claim: AliasClaim{Email: "device-1", Fingerprint: strings.Repeat("ab", 32)}, Local: owner != "master", Enabled: true, Limit: 1000}}
	}
	a := rows["master"]["device-1"]
	a.Children = []string{"node-a", "node-b"}
	rows["master"]["device-1"] = a
	b := PlanBuilder{Authority: authority, Keys: keys}
	b.Inspect = func(ctx context.Context, owner string, signed SignedInspection) (Inventory, error) {
		r, err := VerifyInspection(signed, authority.Public().(ed25519.PublicKey), owner, time.Now().Unix())
		if err != nil {
			return Inventory{}, err
		}
		out := Inventory{Owner: owner, RequestHash: InspectionHash(r)}
		for _, email := range r.Emails {
			alias, ok := rows[owner][email]
			if !ok {
				return Inventory{}, errors.New("missing alias")
			}
			out.Aliases = append(out.Aliases, alias)
		}
		return SignInventory(out, private[owner])
	}
	return b, rows
}

func TestEnrollmentPlannerDiscoversSignedForestAndControlOnlyMaster(t *testing.T) {
	b, rows := plannerFixture(t)
	p, weights, err := b.Enrollment(context.Background(), "sub", []LegacyRoot{{Owner: "master", Alias: "device-1"}})
	if err != nil || len(p.Claims) != 3 || weights["master"] != 0 || weights["node-a"] != 1 || weights["node-b"] != 1 {
		t.Fatal(p, weights, err)
	}
	if err := b.CheckReady(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	a := rows["node-a"]["device-1"]
	a.Claim.Fingerprint = strings.Repeat("cd", 32)
	rows["node-a"]["device-1"] = a
	if b.CheckReady(context.Background(), p) == nil {
		t.Fatal("accepted changed inbound credentials")
	}
}

func TestEnrollmentPlannerRejectsMissingUntrustedAndDuplicateMembers(t *testing.T) {
	for _, scenario := range []string{"missing", "untrusted", "cycle", "double-root", "pending", "enrolled", "relative-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			b, rows := plannerFixture(t)
			roots := []LegacyRoot{{Owner: "master", Alias: "device-1"}}
			a := rows["node-a"]["device-1"]
			switch scenario {
			case "missing":
				delete(rows, "node-b")
			case "untrusted":
				delete(b.Keys, "node-b")
			case "cycle":
				a.Children = []string{"master"}
			case "double-root":
				roots = append(roots, LegacyRoot{Owner: "node-a", Alias: "device-1"})
			case "pending":
				a.Pending = true
			case "enrolled":
				a.Subscription = "other"
			case "relative-expiry":
				a.ExpiresAt = -1000
			}
			rows["node-a"]["device-1"] = a
			if _, _, err := b.Enrollment(context.Background(), "sub", roots); err == nil {
				t.Fatal("unsafe inventory accepted")
			}
		})
	}
}

func TestTransitionPlannerRetainsExactOldMembership(t *testing.T) {
	b, rows := plannerFixture(t)
	previous, _, err := b.Enrollment(context.Background(), "sub", []LegacyRoot{{Owner: "master", Alias: "device-1"}})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Subscription: "sub", Epoch: previous.NextEpoch, Keys: b.Keys}
	for owner := range rows {
		a := rows[owner]["device-1"]
		a.Subscription = "sub"
		a.Epoch = p.Epoch
		a.Children = nil
		rows[owner]["device-1"] = a
	}
	next, err := b.Transition(context.Background(), "renew", previous, p)
	if err != nil || len(next.Claims) != 3 || len(next.AccountingRoots) != 0 || next.Epoch != p.Epoch {
		t.Fatal(next, err)
	}
	delete(rows, "node-b")
	if _, err = b.Transition(context.Background(), "reset", previous, p); err == nil {
		t.Fatal("silently dropped missing old member")
	}
}
