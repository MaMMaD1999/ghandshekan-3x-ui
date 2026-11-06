package nodee2e

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xray/meshgate"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// This goes through a real panel's scheduled traffic job. It never directly
// fences the user: the quota/expiry decision must reach the core by itself.
func TestAutomaticQuotaCutoffWithoutRestart(t *testing.T) {
	core := os.Getenv("MESH_TEST_CORE")
	if core == "" {
		t.Skip("MESH_TEST_CORE is not set")
	}
	bin := panelBinary(t)
	for _, mode := range []string{"volume", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			p := newPanel(t, bin, "quota-"+mode)
			apiPort, inboundPort := freePort(t), freePort(t)
			contents, err := os.ReadFile(core)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(p.dir, "bin", xray.GetBinaryName()), contents, 0700); err != nil {
				t.Fatal(err)
			}
			template := fmt.Sprintf(`{"log":{"loglevel":"warning"},"stats":{},"api":{"tag":"api","services":["StatsService","HandlerService","RoutingService"]},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}],"outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}},{"protocol":"blackhole","tag":"blocked"}],"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}`, apiPort)
			func() {
				sharedDBMu.Lock()
				defer sharedDBMu.Unlock()
				if err := database.InitDB(filepath.Join(p.dir, "db", "x-ui.db")); err != nil {
					t.Fatal(err)
				}
				defer database.CloseDB()
				for key, value := range map[string]string{"xrayTemplateConfig": template, "restartXrayOnClientDisable": "false"} {
					db := database.GetDB()
					if err := db.Exec("DELETE FROM settings WHERE key = ?", key).Error; err != nil {
						t.Fatal(err)
					}
					if err := db.Exec("INSERT INTO settings(key,value) VALUES (?,?)", key, value).Error; err != nil {
						t.Fatal(err)
					}
				}
			}()
			p.start()
			t.Cleanup(func() { _, _ = p.try(http.MethodPost, "/panel/api/server/stopXrayService", nil) })
			limited, other := vlessClient("limited"), vlessClient("other")
			if mode == "volume" {
				limited["totalGB"] = int64(1 << 20)
			} else {
				limited["expiryTime"] = time.Now().Add(10 * time.Second).UnixMilli()
			}
			inbound := vlessInbound("quota-test", inboundPort, nil, limited, other)
			inbound["listen"] = "127.0.0.1"
			p.call(http.MethodPost, "/panel/api/inbounds/add", inbound)
			p.call(http.MethodPost, "/panel/api/server/reconcileXrayService", nil)
			conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			state := func() string {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				r := new(meshgate.State)
				if err := conn.Invoke(ctx, "/xray.app.stats.command.StatsService/GetUserGates", &meshgate.GetRequest{Scope: "config"}, r); err != nil {
					t.Fatal(err)
				}
				return r.Instance
			}
			before := state()
			payload := make([]byte, 16<<10)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for {
					if _, err := w.Write(payload); err != nil {
						return
					}
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(5 * time.Millisecond):
					}
				}
			}))
			defer target.Close()
			limitedClient := quotaProxyClient(t, core, inboundPort, newUUID("limited"))
			otherClient := quotaProxyClient(t, core, inboundPort, newUUID("other"))
			otherStream, err := otherClient.Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer otherStream.Body.Close()
			var otherBytes quotaByteCounter
			otherDone := make(chan error, 1)
			go func() { _, err := io.Copy(&otherBytes, otherStream.Body); otherDone <- err }()
			response, err := limitedClient.Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			first := make([]byte, 1024)
			if _, err = io.ReadFull(response.Body, first); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, response.Body); close(done) }()
			select {
			case <-done:
			case <-time.After(18 * time.Second):
				t.Fatal("quota/expiry did not terminate ongoing download")
			}
			ib, found := p.inboundOnPort(inboundPort)
			if !found || ib.client("limited")["enable"] != false {
				t.Fatal("stream stopped without panel disabling depleted user")
			}
			if after := state(); after != before {
				t.Fatal("whole core restarted and interrupted other users")
			}
			baseline := otherBytes.bytes.Load()
			eventually(t, 2*time.Second, "unrelated existing stream still transfers", func() (bool, string) {
				select {
				case err := <-otherDone:
					t.Fatalf("unrelated stream ended: %v", err)
				default:
				}
				return otherBytes.bytes.Load() > baseline, "no new bytes on unrelated stream"
			})
		})
	}
}

type quotaByteCounter struct{ bytes atomic.Int64 }

func (w *quotaByteCounter) Write(p []byte) (int, error) {
	w.bytes.Add(int64(len(p)))
	return len(p), nil
}

func quotaProxyClient(t *testing.T, core string, inboundPort int, id string) *http.Client {
	t.Helper()
	port := freePort(t)
	dir := t.TempDir()
	config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"%s","encryption":"none"}]}]}}]}`, port, inboundPort, id)
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 5*time.Second, "client SOCKS listener", func() (bool, string) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			return false, err.Error()
		}
		conn.Close()
		return true, ""
	})
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 35 * time.Second}
}
