package meshconsensus

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestRelativeAdjustmentUsesCommittedPolicyAndSurvivesRetry(t *testing.T) {
	c := cluster(t, 3)
	n := c.leader(c.ids())
	p := c.base()
	p.ExpiresAt = time.Now().Add(time.Hour).Unix()
	reg, err := SignRegistration(p, c.authority)
	if err != nil {
		t.Fatal(err)
	}
	execute(t, n, Command{ID: "register", Registration: &reg})
	first := Command{ID: "bulk-first", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 100, AddSeconds: 3600}}
	second := Command{ID: "bulk-second", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 200, AddSeconds: 7200}}
	a := execute(t, n, first)
	execute(t, n, second)
	repeated := execute(t, n, first)
	if repeated.Update.Next.Version != a.Update.Next.Version {
		t.Fatal("retry created another adjustment")
	}
	current, err := n.FSM.Policy(p.Subscription)
	if err != nil || current.Limit != 10300 || current.ExpiresAt != p.ExpiresAt+10800 || current.ResetGeneration != 1 {
		t.Fatal("lost or repeated relative adjustment", current, err)
	}
	for i, patch := range []*PolicyPatch{
		{AddBytes: -10300}, {AddBytes: math.MaxInt64}, {AddSeconds: math.MinInt64},
		{Limit: &p.Limit, AddBytes: 1}, {ExpiresAt: &p.ExpiresAt, AddSeconds: 1},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := n.Execute(ctx, Command{ID: string(rune('a' + i)), Subscription: p.Subscription, Kind: "renew", Patch: patch})
		cancel()
		if err == nil {
			t.Fatal("invalid adjustment was accepted", i)
		}
	}
	after, _ := n.FSM.Policy(p.Subscription)
	if after.Version != current.Version || after.Limit != current.Limit {
		t.Fatal("failed request altered policy")
	}
	unlimited, zero := true, int64(0)
	execute(t, n, Command{ID: "make-unlimited", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{Limit: &zero, ExpiresAt: &zero, Unlimited: &unlimited}})
	out := execute(t, n, Command{ID: "unlimited-bulk", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{AddBytes: 100, AddSeconds: 3600}})
	if !out.Update.Next.Unlimited || out.Update.Next.Limit != 0 || out.Update.Next.ExpiresAt != 0 {
		t.Fatal("bulk unexpectedly restricted unlimited plan")
	}
}

func TestFiniteZeroQuotaCanBeIncreased(t *testing.T) {
	if n, err := adjustPositive(0, 100, math.MaxInt64); err != nil || n != 100 {
		t.Fatal(n, err)
	}
}
