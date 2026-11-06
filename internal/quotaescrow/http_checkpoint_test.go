//go:build cgo

package quotaescrow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestExchangeDoesNotPublishBeforeRestoreCheckpointCommits(t *testing.T) {
	p, keys := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "quota.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	contacted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted = true; w.WriteHeader(500) }))
	defer server.Close()
	h := HTTPExchange{Store: s, Owner: "de", Key: keys["de"], Subscription: p.Subscription, Peers: map[string]string{"at": server.URL}, Client: server.Client(), Checkpoint: func() error { return errors.New("checkpoint disk failed") }}
	if err := h.Attempt(context.Background(), "at", "at", nil); err == nil || contacted {
		t.Fatal("unchecked rows escaped", err, contacted)
	}
}

func TestExchangeWithholdsReceiptWhenCheckpointFailsAfterMerge(t *testing.T) {
	p, keys := fixture(t)
	s, close := openStore(t, filepath.Join(t.TempDir(), "quota.db"))
	defer close()
	if err := s.Create(p); err != nil {
		t.Fatal(err)
	}
	remote := ledger(t, p)
	row := apply(t, remote, "de", keys["de"], 50, "")
	request, err := NewExchange(p, "de", "at", keys["de"], []SignedRow{row})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(request)
	calls := 0
	h := HTTPExchange{Store: s, Owner: "at", Key: keys["at"], Checkpoint: func() error {
		calls++
		if calls == 2 {
			return errors.New("checkpoint full")
		}
		return nil
	}}
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/exchange", strings.NewReader(string(body))))
	if response.Code != http.StatusServiceUnavailable || calls != 2 {
		t.Fatal(response.Code, calls)
	}
	if strings.Contains(response.Body.String(), "signature") {
		t.Fatal("uncheckpointed receipt escaped")
	}
}
