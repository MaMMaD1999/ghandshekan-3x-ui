package quotaescrow

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func aliasFixture(t *testing.T) (Policy, map[string]ed25519.PrivateKey) {
	t.Helper()
	p, keys := fixture(t)
	p.Mode, p.Version, p.ResetGeneration = "shared", 1, 1
	p.ControlEpoch, p.ControlKeys = "cluster", clone(p.Keys)
	p.Authority, _, _ = ed25519.GenerateKey(nil)
	p.Manager, p.AlreadyBilled = "de", 123
	for id := range p.Grants {
		p.Grants[id] = 0
	}
	p.Aliases = AliasCatalog{"de": {"phone": {Fingerprint: strings.Repeat("ab", 32), Revision: 1}}}
	if _, err := New(p); err != nil {
		t.Fatal(err)
	}
	return p, keys
}

func certifyAlias(t *testing.T, p Policy, u PolicyUpdate, keys map[string]ed25519.PrivateKey) PolicyUpdate {
	t.Helper()
	u.Votes = map[string][]byte{}
	for _, id := range []string{"de", "at"} {
		u.Votes[id] = PolicyUpdateVote(u, keys[id])
	}
	if err := VerifyPolicyUpdate(p, u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAliasAuthorizationDoesNotChangeBillingOrOtherDevices(t *testing.T) {
	p, keys := aliasFixture(t)
	u, err := DraftAliasChange(p, "add-tablet", AliasPatch{Owner: "de", Email: "tablet", Fingerprint: strings.Repeat("cd", 32)})
	if err != nil {
		t.Fatal(err)
	}
	u = certifyAlias(t, p, u, keys)
	if u.Next.Limit != p.Limit || u.Next.AlreadyBilled != 123 || u.Next.Epoch != p.Epoch || u.Next.ResetGeneration != 1 || u.Next.ExpiresAt != p.ExpiresAt || u.Next.Aliases["de"]["phone"] != p.Aliases["de"]["phone"] {
		t.Fatal("alias operation changed accounting or another device")
	}
	for name, mutate := range map[string]func(*PolicyUpdate){
		"quota":    func(v *PolicyUpdate) { v.Next.Limit++ },
		"baseline": func(v *PolicyUpdate) { v.Next.AlreadyBilled = 0 },
		"reset":    func(v *PolicyUpdate) { v.Next.ResetGeneration++ },
		"drop":     func(v *PolicyUpdate) { delete(v.Next.Aliases["de"], "phone") },
		"second": func(v *PolicyUpdate) {
			v.Next.Aliases["de"]["other"] = AliasAuthorization{Fingerprint: strings.Repeat("ef", 32), Revision: 1}
		},
		"key": func(v *PolicyUpdate) { v.Next.Keys["de"] = keys["at"].Public().(ed25519.PublicKey) },
	} {
		t.Run(name, func(t *testing.T) {
			v := clone(u)
			mutate(&v)
			if VerifyPolicyShape(p, v) == nil {
				t.Fatal("unauthorized mutation accepted")
			}
		})
	}
	unsigned := u
	unsigned.Votes = nil
	if VerifyPolicyUpdate(p, unsigned) == nil {
		t.Fatal("unsigned alias authorization accepted")
	}
	minority := clone(u)
	delete(minority.Votes, "at")
	if VerifyPolicyUpdate(p, minority) == nil {
		t.Fatal("isolated member authorized a device")
	}
}

func TestAliasCheckpointRetainsRevocationAndExactMeterIdentity(t *testing.T) {
	p, keys := aliasFixture(t)
	first, err := DraftAliasChange(p, "revoke-phone", AliasPatch{Owner: "de", Email: "phone", ExpectedRevision: 1, Fingerprint: strings.Repeat("ab", 32), Revoked: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := DraftAliasChange(first.Next, "add-tablet", AliasPatch{Owner: "at", Email: "tablet", Fingerprint: strings.Repeat("cd", 32)})
	if err != nil {
		t.Fatal(err)
	}
	second = certifyAlias(t, p, second, keys)
	if !second.Next.Aliases["de"]["phone"].Revoked || second.Next.Aliases["de"]["phone"].Revision != 2 {
		t.Fatal("lost revocation")
	}
	if VerifyPolicyUpdate(second.Next, first) == nil {
		t.Fatal("old alias certificate reversed latest state")
	}
	bad := clone(second)
	delete(bad.Next.Aliases["de"], "phone")
	if VerifyPolicyCheckpointShape(p, bad) == nil {
		t.Fatal("checkpoint forgot revocation tombstone")
	}
	bad = clone(second)
	bad.Next.ResetGeneration++
	if VerifyPolicyCheckpointShape(p, bad) == nil {
		t.Fatal("impossible extra reset accepted")
	}
	if _, err := DraftAliasChange(second.Next, "stale-revive", AliasPatch{Owner: "de", Email: "phone", ExpectedRevision: 1, Fingerprint: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("stale update resurrected device")
	}
	if _, err := DraftAliasChange(second.Next, "unknown-owner", AliasPatch{Owner: "unregistered", Email: "phone", Fingerprint: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("new metering owner inferred")
	}
}

func TestLegacyPolicyCannotSilentlyGainMutableMembership(t *testing.T) {
	p, _ := aliasFixture(t)
	p.Aliases = nil
	if _, err := DraftAliasChange(p, "implicit-migrate", AliasPatch{Owner: "de", Email: "phone", Fingerprint: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("legacy membership guessed")
	}
}
