//go:build cgo

package quotaescrow

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestSharedPolicyGossipThroughRelayWithAuthorityOffline(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	stores := map[string]*Store{}
	for _, owner := range []string{"at", "de", "nl"} {
		stores[owner] = rollingStore(t, p, owner)
	}
	apply := func(owner string) func(context.Context, string, []PolicyUpdate) error {
		return func(_ context.Context, subscription string, updates []PolicyUpdate) error {
			needed, err := stores[owner].BeginSharedUpdates(subscription, updates)
			if err != nil || !needed {
				return err
			}
			_, _, err = stores[owner].CommitSharedUpdates(subscription, owner, keys[owner])
			return err
		}
	}
	u, _ := SignPolicyUpdate(p, "reset-away", "reset", 1000, 0, authority)
	if err := apply("at")(context.Background(), p.Subscription, []PolicyUpdate{u}); err != nil {
		t.Fatal(err)
	}
	if err := stores["at"].Observe(p.Subscription, "at", keys["at"], 20, 100); err != nil {
		t.Fatal(err)
	}
	peers := map[string]string{}
	dest := httptest.NewTLSServer(HTTPExchange{Store: stores["nl"], Owner: "nl", Key: keys["nl"], Peers: peers, ApplyUpdates: apply("nl")}.Handler())
	defer dest.Close()
	peers["nl"] = dest.URL
	relay := httptest.NewTLSServer(HTTPExchange{Store: stores["de"], Owner: "de", Key: keys["de"], Peers: peers, Client: dest.Client(), ApplyUpdates: apply("de")}.Handler())
	defer relay.Close()
	peers["de"] = relay.URL
	exchange := HTTPExchange{Store: stores["at"], Owner: "at", Key: keys["at"], Peers: peers, Client: dest.Client(), ApplyUpdates: apply("at"), Subscription: p.Subscription}
	l, _ := stores["at"].Load(p.Subscription)
	transport := SyncTransport{Direct: func(context.Context, string, string, []SignedRow) error { return errors.New("direct blocked") }, Relay: exchange.Attempt}
	for i := 0; i < 3; i++ {
		path, err := transport.Sync(context.Background(), "nl", []string{"de"}, l.Snapshot())
		if err != nil || path != "relay" {
			t.Fatal("policy not relayed", path, err)
		}
	}
	for owner, s := range stores {
		l, err := s.Load(p.Subscription)
		if err != nil {
			t.Fatal(owner, err)
		}
		if l.policy.Version != 2 {
			t.Fatal(owner, "did not learn reset")
		}
		assertBilled(t, l, 20)
	}
}

func TestSharedOlderInitiatorLearnsNewPolicyFromReceipt(t *testing.T) {
	p, keys, authority := rollingFixture(t)
	a, b := rollingStore(t, p, "a"), rollingStore(t, p, "b")
	u, _ := SignPolicyUpdate(p, "renew", "renew", 2000, 0, authority)
	applyRolling(t, b, "nl", keys["nl"], u)
	server := httptest.NewTLSServer(HTTPExchange{Store: b, Owner: "nl", Key: keys["nl"], ApplyUpdates: func(context.Context, string, []PolicyUpdate) error { return nil }}.Handler())
	defer server.Close()
	exchange := HTTPExchange{Store: a, Owner: "at", Key: keys["at"], Peers: map[string]string{"nl": server.URL}, Client: server.Client(), Subscription: p.Subscription, ApplyUpdates: func(_ context.Context, sub string, updates []PolicyUpdate) error {
		needed, err := a.BeginSharedUpdates(sub, updates)
		if err != nil || !needed {
			return err
		}
		_, _, err = a.CommitSharedUpdates(sub, "at", keys["at"])
		return err
	}}
	l, _ := a.Load(p.Subscription)
	if err := exchange.Attempt(context.Background(), "nl", "nl", l.Snapshot()); err != nil {
		t.Fatal(err)
	}
	l, _ = a.Load(p.Subscription)
	if l.policy.Version != 2 || l.policy.Limit != 2000 {
		t.Fatal("receipt did not apply renewal")
	}
}
