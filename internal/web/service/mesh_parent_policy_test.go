package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestParentLifecycleCommandBindsScopeAndImmutableCAS(t *testing.T) {
	p := quotaescrow.Policy{Subscription: "parent", ControlEpoch: "cluster", Epoch: "lifetime", Mode: "shared", Aliases: quotaescrow.AliasCatalog{}}
	b := false
	input := MeshParentPolicyInput{Subscription: p.Subscription, ControlEpoch: p.ControlEpoch, Epoch: p.Epoch,
		ExpectedHash: strings.Repeat("ab", 32), Kind: "reset", Limit: 2000, Disabled: &b, Unlimited: &b}
	c, err := parentPolicyCommand(input, "reset-once", p)
	if err != nil || c.ExpectedHash != input.ExpectedHash || c.Patch == nil || *c.Patch.Limit != 2000 {
		t.Fatal(c, err)
	}
	// An already accepted retry may reach a later local policy. Only consensus
	// may decide whether this is a receipt lookup or a stale unaccepted command.
	p.Limit, p.Version = 5000, 5
	retry, err := parentPolicyCommand(input, "reset-once", p)
	if err != nil || retry.ID != c.ID || retry.ExpectedHash != c.ExpectedHash {
		t.Fatal(retry, err)
	}
	for _, change := range []func(*MeshParentPolicyInput){
		func(i *MeshParentPolicyInput) { i.ControlEpoch = "foreign" },
		func(i *MeshParentPolicyInput) { i.Epoch = "foreign" },
		func(i *MeshParentPolicyInput) { i.Subscription = "foreign" },
		func(i *MeshParentPolicyInput) { i.ExpectedHash = "" },
		func(i *MeshParentPolicyInput) { i.ExpectedHash = strings.ToUpper(i.ExpectedHash) },
		func(i *MeshParentPolicyInput) { i.Kind = "enroll" },
		func(i *MeshParentPolicyInput) { i.Disabled = nil },
		func(i *MeshParentPolicyInput) { i.Unlimited = nil },
		func(i *MeshParentPolicyInput) { i.Limit = -1 },
	} {
		bad := input
		change(&bad)
		if _, err := parentPolicyCommand(bad, "key", p); err == nil {
			t.Fatal("unsafe parent request accepted", bad)
		}
	}
	if _, err := parentPolicyCommand(input, "", p); err == nil {
		t.Fatal("missing stable retry key accepted")
	}
}

func TestLegacyAbsoluteRenewalPinsItsObservedPolicyWithoutResettingUsage(t *testing.T) {
	p := quotaescrow.Policy{Subscription: "parent", Epoch: "life", ControlEpoch: "control", Version: 4}
	a, key := legacyAbsoluteMeshRequest(p, 5000, 1800000000, false, false)
	b, same := legacyAbsoluteMeshRequest(p, 5000, 1800000000, false, false)
	if key != same || a.ExpectedHash != b.ExpectedHash || a.Kind != "renew" {
		t.Fatal(a, b)
	}
	p.Version++
	c, newer := legacyAbsoluteMeshRequest(p, 5000, 1800000000, false, false)
	if key == newer || a.ExpectedHash == c.ExpectedHash {
		t.Fatal("stale legacy renewal lost its CAS")
	}
}
