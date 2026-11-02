//go:build cgo

package quotaescrow

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerSyncContinuesWithoutMasterAndConvergesAfterReconnect(t *testing.T) {
	p, keys := fixture(t)
	stores := map[string]*Store{}
	for _, id := range []string{"at", "de", "nl"} {
		s, close := openStore(t, filepath.Join(t.TempDir(), id+".db"))
		t.Cleanup(close)
		if err := s.Create(p); err != nil {
			t.Fatal(err)
		}
		stores[id] = s
	}
	// DE represents the offline master. AT and NL can still exchange signed
	// usage over real HTTPS, without a request succeeding against DE.
	peer := httptest.NewTLSServer(HTTPExchange{Store: stores["nl"], Owner: "nl", Key: keys["nl"]}.Handler())
	defer peer.Close()
	exchange := HTTPExchange{Store: stores["at"], Owner: "at", Key: keys["at"], Subscription: p.Subscription, Peers: map[string]string{"nl": peer.URL}, Client: peer.Client()}
	if err := stores["at"].Observe(p.Subscription, "at", keys["at"], 120, 100); err != nil {
		t.Fatal(err)
	}
	if err := stores["nl"].Observe(p.Subscription, "nl", keys["nl"], 80, 100); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		results, err := stores["at"].SyncSubscription(context.Background(), p.Subscription, "at", SyncTransport{Direct: exchange.Attempt})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			if r.Peer == "de" && r.Err == nil {
				t.Fatal("offline master acknowledged")
			}
			if r.Peer == "nl" && (r.Err != nil || r.Path != "direct") {
				t.Fatal(r)
			}
		}
	}
	for _, id := range []string{"at", "nl"} {
		l, err := stores[id].Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		assertBilled(t, l, 200)
		if n, err := stores[id].Admission(p.Subscription, id, 5000); err != nil || n != 0 {
			t.Fatal("expiry depends on master", n, err)
		}
	}
	master := httptest.NewTLSServer(HTTPExchange{Store: stores["de"], Owner: "de", Key: keys["de"]}.Handler())
	defer master.Close()
	exchange.Peers["de"] = master.URL
	results, err := stores["at"].SyncSubscription(context.Background(), p.Subscription, "at", SyncTransport{Direct: exchange.Attempt})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	l, err := stores["de"].Load(p.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	assertBilled(t, l, 200)
}

func TestSlowPeerDoesNotSerializeHealthyPeer(t *testing.T) {
	p, _ := fixture(t)
	s, closeStore := openStore(t, filepath.Join(t.TempDir(), "sync.db"))
	defer closeStore()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	healthy := make(chan struct{})
	transport := SyncTransport{Direct: func(ctx context.Context, destination, _ string, _ []SignedRow) error {
		if destination == "nl" {
			close(healthy)
			return nil
		}
		select {
		case <-healthy:
			return errors.New("offline")
		case <-ctx.Done():
			return ctx.Err()
		}
	}, AttemptTimeout: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results, err := s.SyncSubscription(ctx, p.Subscription, "at", transport)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Peer == "de" && errors.Is(r.Err, context.DeadlineExceeded) {
			t.Fatal("healthy peer waited behind offline peer")
		}
	}
}

func TestSyncScheduleStopsWithoutOverlappingCycles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	count := 0
	err := RunSync(ctx, time.Millisecond, func(ctx context.Context) {
		count++
		if count == 3 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || count != 3 {
		t.Fatal(err, count)
	}
	if err := RunSync(context.Background(), 0, func(context.Context) {}); err == nil {
		t.Fatal("unbounded schedule accepted")
	}
}
