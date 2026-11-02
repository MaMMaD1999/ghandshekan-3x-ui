//go:build cgo

package quotaescrow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSExchangeThroughRelayKeepsAccountingIdempotent(t *testing.T) {
	p, k := fixture(t)
	stores := map[string]*Store{}
	for _, id := range []string{"at", "de", "nl"} {
		s, close := openStore(t, filepath.Join(t.TempDir(), id+".db"))
		t.Cleanup(close)
		if err := s.Create(p); err != nil {
			t.Fatal(err)
		}
		stores[id] = s
	}
	peers := map[string]string{}
	// httptest's client trusts its test certificate, not arbitrary certificates.
	destination := httptest.NewTLSServer(HTTPExchange{Store: stores["nl"], Owner: "nl", Key: k["nl"], Peers: peers}.Handler())
	defer destination.Close()
	peers["nl"] = destination.URL
	relay := httptest.NewTLSServer(HTTPExchange{Store: stores["de"], Owner: "de", Key: k["de"], Peers: peers, Client: destination.Client()}.Handler())
	defer relay.Close()
	peers["de"] = relay.URL
	a := HTTPExchange{Store: stores["at"], Owner: "at", Key: k["at"], Subscription: p.Subscription, Peers: peers, Client: destination.Client()}
	if err := stores["at"].Observe(p.Subscription, "at", k["at"], 120, 100); err != nil {
		t.Fatal(err)
	}
	l, _ := stores["at"].Load(p.Subscription)
	directAttempts := 0
	transport := SyncTransport{Direct: func(context.Context, string, string, []SignedRow) error {
		directAttempts++
		return errors.New("direct path unavailable")
	}, Relay: a.Attempt}
	for i := 0; i < 3; i++ {
		path, err := transport.Sync(context.Background(), "nl", []string{"de"}, l.Snapshot())
		if err != nil || path != "relay" {
			t.Fatalf("relay sync: %s %v", path, err)
		}
	}
	if directAttempts != 3 {
		t.Fatal("fallback bypassed direct preference on next cycle")
	}
	for _, s := range stores {
		got, err := s.Load(p.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		assertBilled(t, got, 120)
	}
}

func TestExchangeHTTPRejectsRedirectsAndUnprovisionedPeers(t *testing.T) {
	hits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	h := HTTPExchange{Peers: map[string]string{"peer": redirect.URL, "plain": "http://example.org"}, Client: redirect.Client()}
	for _, peer := range []string{"peer", "plain", "missing"} {
		if _, err := h.post(context.Background(), peer, SignedExchange{}, false); err == nil {
			t.Fatal("unsafe transport accepted", peer)
		}
	}
	if hits != 0 {
		t.Fatal("accounting payload forwarded through redirect")
	}
	if _, err := decodeExchange(strings.NewReader(strings.Repeat("x", maxExchangeBytes+1))); err == nil {
		t.Fatal("oversized exchange accepted")
	}
	if _, err := decodeExchange(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}
