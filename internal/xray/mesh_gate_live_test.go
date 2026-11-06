//go:build meshcore

package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Three isolated core processes exercise the real VLESS and SOCKS paths. No
// public network or production inbound is used. Set MESH_TEST_CORE explicitly.
func TestMeshGateLiveTraffic(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%v", protocol, mux), func(t *testing.T) { testMeshGateLiveTraffic(t, protocol, mux) })
		}
	}
}

func testMeshGateLiveTraffic(t *testing.T, protocol string, mux bool) {
	binary := os.Getenv("MESH_TEST_CORE")
	if binary == "" {
		t.Skip("MESH_TEST_CORE is not set")
	}
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	serverPort, apiPort, phonePort, otherPort := port(), port(), port(), port()
	start := func(name, config string, readyPort int) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.Create(filepath.Join(dir, "core.log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-c", configPath)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			log.Close()
			if t.Failed() {
				body, _ := os.ReadFile(filepath.Join(dir, "core.log"))
				t.Logf("%s: %s", name, body)
			}
		})
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", readyPort), 100*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
		body, _ := os.ReadFile(filepath.Join(dir, "core.log"))
		t.Fatalf("%s did not start: %s", name, body)
	}
	const phoneID = "ee4b22db-e583-4b11-a2d2-84df9017c832"
	const otherID = "6d83d4ac-f1c4-4d05-87b4-9485471845b0"
	identityField := "id"
	if protocol == "trojan" {
		identityField = "password"
	}
	serverSettings := fmt.Sprintf(`{"clients":[{"%s":"%s","email":"phone"},{"%s":"%s","email":"other"}],"decryption":"none"}`, identityField, phoneID, identityField, otherID)
	start("server", fmt.Sprintf(`{"log":{"loglevel":"warning"},"stats":{},"api":{"tag":"api","services":["StatsService"]},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},{"tag":"users","listen":"127.0.0.1","port":%d,"protocol":"%s","settings":%s}],"outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}],"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}`, apiPort, serverPort, protocol, serverSettings), apiPort)
	client := func(name, id string, socksPort int) *http.Client {
		settings := fmt.Sprintf(`{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none","security":"auto"}]}]}`, serverPort, id)
		if protocol == "trojan" {
			settings = fmt.Sprintf(`{"servers":[{"address":"127.0.0.1","port":%d,"password":"%s"}]}`, serverPort, id)
		}
		start(name, fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"%s","settings":%s,"mux":{"enabled":%v,"concurrency":4}}]}`, socksPort, protocol, settings, mux), socksPort)
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	phone, other := client("phone", phoneID, phonePort), client("other", otherID, otherPort)
	payload := make([]byte, 64<<10)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		for {
			if _, err := w.Write(payload); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}))
	defer target.Close()
	response, err := phone.Get(target.URL + "/stream")
	if err != nil {
		t.Fatal("initial traffic", err)
	}
	defer response.Body.Close()
	var first [1]byte
	if _, err = io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal(err)
	}
	api := &XrayAPI{}
	if err = api.Init(apiPort); err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = api.ReconcileConfigGates(ctx, []string{"phone", "other"}, []string{"phone", "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal("credential-preserving update cut active stream", err)
	}
	if err = api.ReconcileConfigGates(ctx, []string{"phone", "other"}, []string{"other"}); err != nil {
		t.Fatal(err)
	}
	drain, releaseDrain := context.WithTimeout(ctx, 3*time.Second)
	if err = api.WaitUserSessionsFor(drain, "config", []string{"phone"}); err != nil {
		releaseDrain()
		t.Fatal("fenced protocol did not drain", err)
	}
	releaseDrain()
	if _, _, err := api.GetTraffic(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_, settled, err := api.GetTraffic()
	if err != nil {
		t.Fatal(err)
	}
	for _, traffic := range settled {
		if traffic.Email == "phone" && traffic.Up+traffic.Down != 0 {
			t.Fatal("counter changed after drain", traffic)
		}
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, response.Body); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("existing user stream survived gate")
	}
	if r, err := phone.Get(target.URL); err == nil {
		r.Body.Close()
		t.Fatal("new blocked request succeeded")
	}
	r, err := other.Get(target.URL)
	if err != nil {
		t.Fatal("unrelated user was interrupted", err)
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatal("unrelated user lost traffic", string(body), err)
	}
	if err = api.ReconcileUserGates(ctx, []string{"phone"}); err != nil {
		t.Fatal(err)
	}
	if err = api.ReconcileConfigGates(ctx, []string{"other"}, []string{"phone", "other"}); err != nil {
		t.Fatal(err)
	}
	if r, err := phone.Get(target.URL); err == nil {
		r.Body.Close()
		t.Fatal("config renewal bypassed mesh gate")
	}
	if err = api.ReconcileUserGates(ctx, nil); err != nil {
		t.Fatal(err)
	}
	r, err = phone.Get(target.URL)
	if err != nil {
		t.Fatal("unblocked user did not reconnect", err)
	}
	r.Body.Close()
}
