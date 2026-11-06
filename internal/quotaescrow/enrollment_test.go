package quotaescrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEnrollmentBindsAuthorityMembershipAndAliases(t *testing.T) {
	p, keys := fixture(t)
	pub, authority, _ := ed25519.GenerateKey(rand.Reader)
	aliases := map[string][]string{}
	for owner := range p.Keys {
		aliases[owner] = []string{"user-" + owner}
	}
	e := Enrollment{Policy: p, Aliases: aliases, IssuedAt: 100, ValidUntil: 200}
	signed, err := SignEnrollment(e, authority)
	if err != nil {
		t.Fatal(err)
	}
	local := keys["de"].Public().(ed25519.PublicKey)
	policy, names, err := VerifyEnrollment(signed, pub, "de", local, 150)
	if err != nil || policy.Subscription != p.Subscription || len(names) != 1 || names[0] != "user-de" {
		t.Fatal(policy, names, err)
	}
	// Returned objects cannot mutate the signed policy or another node's aliases.
	policy.Grants["de"] = 0
	names[0] = "changed"
	if signed.Enrollment.Policy.Grants["de"] != p.Grants["de"] || signed.Enrollment.Aliases["de"][0] != "user-de" {
		t.Fatal("mutable enrollment escaped")
	}
	for _, now := range []int64{99, 200, 1000} {
		if _, _, err := VerifyEnrollment(signed, pub, "de", local, now); err == nil {
			t.Fatal("accepted stale/future enrollment", now)
		}
	}
	if _, _, err := VerifyEnrollment(signed, pub, "at", local, 150); err == nil {
		t.Fatal("accepted wrong node key")
	}
	if _, _, err := VerifyEnrollment(signed, local, "de", local, 150); err == nil {
		t.Fatal("peer key accepted as authority")
	}
	peerSigned, err := SignEnrollment(e, keys["de"])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyEnrollment(peerSigned, local, "de", local, 150); err == nil {
		t.Fatal("peer also acted as enrollment authority")
	}
	duplicateKeys := clone(e)
	duplicateKeys.Policy.Keys["at"] = duplicateKeys.Policy.Keys["de"]
	if _, err := SignEnrollment(duplicateKeys, authority); err == nil {
		t.Fatal("accepted shared node signing key")
	}
	tampered := clone(signed)
	tampered.Enrollment.Aliases["de"][0] = "someone-else"
	if _, _, err := VerifyEnrollment(tampered, pub, "de", local, 150); err == nil {
		t.Fatal("accepted substituted alias")
	}
	tampered = clone(signed)
	tampered.Enrollment.Policy.Limit++
	if _, _, err := VerifyEnrollment(tampered, pub, "de", local, 150); err == nil {
		t.Fatal("accepted changed quota")
	}
	delete(e.Aliases, "de")
	if _, err := SignEnrollment(e, authority); err == nil {
		t.Fatal("signed incomplete membership")
	}
}
