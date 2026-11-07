package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlClientRejectsRedirectWrongKeyAndReplay(t *testing.T) {
	key, private, _ := ed25519.GenerateKey(rand.Reader)
	_, authority, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Unix()
	request := Inspection{Owner: "node", Nonce: rand.Text(), Emails: []string{"phone"}, IssuedAt: now - 1, ValidUntil: now + 60}
	signed, err := SignInspection(request, authority)
	if err != nil {
		t.Fatal(err)
	}
	var mode atomic.Value
	mode.Store("ok")
	var receivedRedirect atomic.Bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { receivedRedirect.Store(true) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inspect" {
			t.Error("wrong private path", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if mode.Load() == "redirect" {
			http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
			return
		}
		out := Inventory{Owner: "node", RequestHash: InspectionHash(request), Aliases: []InspectedAlias{{Claim: AliasClaim{Email: "phone", Fingerprint: strings.Repeat("ab", 32)}}}}
		if mode.Load() == "replay" {
			out.RequestHash = strings.Repeat("00", 32)
		}
		out, _ = SignInventory(out, private)
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	client := ControlClient{HTTP: server.Client(), Peers: map[string]string{"node": server.URL + "/exchange"}, Keys: map[string][]byte{"node": key}}
	if _, err := client.Inspect(context.Background(), "node", signed); err != nil {
		t.Fatal(err)
	}
	mode.Store("redirect")
	if _, err := client.Inspect(context.Background(), "node", signed); err == nil || receivedRedirect.Load() {
		t.Fatal("followed redirect or accepted it")
	}
	mode.Store("replay")
	if _, err := client.Inspect(context.Background(), "node", signed); err == nil {
		t.Fatal("accepted another request's response")
	}
	mode.Store("ok")
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	client.Keys["node"] = wrong
	if _, err := client.Inspect(context.Background(), "node", signed); err == nil {
		t.Fatal("trusted unpinned node key")
	}
	client.Peers["node"] = "http://127.0.0.1/exchange"
	if _, err := client.Inspect(context.Background(), "node", signed); err == nil {
		t.Fatal("accepted plaintext endpoint")
	}
}
