package nodee2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// Exercises the mounted private control endpoint, actual protocol/task drain,
// scheduled traffic collector and durable checkpoint rather than test callbacks.
func TestMeshControlRealEnrollmentRenewReset(t *testing.T) {
	core := os.Getenv("MESH_TEST_CORE")
	if core == "" {
		t.Skip("MESH_TEST_CORE not set")
	}
	p := newPanel(t, panelBinary(t), "mesh-control")
	apiPort, inboundPort := freePort(t), freePort(t)
	b, err := os.ReadFile(core)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.dir, "bin", xray.GetBinaryName()), b, 0700); err != nil {
		t.Fatal(err)
	}
	template := fmt.Sprintf(`{"log":{"loglevel":"warning"},"stats":{},"api":{"tag":"api","services":["StatsService","HandlerService","RoutingService"]},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}],"outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}},{"protocol":"blackhole","tag":"blocked"}],"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}`, apiPort)
	withDB := func(fn func()) {
		sharedDBMu.Lock()
		defer sharedDBMu.Unlock()
		if err := database.InitDB(filepath.Join(p.dir, "db", "x-ui.db")); err != nil {
			t.Fatal(err)
		}
		defer database.CloseDB()
		fn()
	}
	withDB(func() {
		for key, value := range map[string]string{"xrayTemplateConfig": template, "restartXrayOnClientDisable": "false"} {
			database.GetDB().Exec("DELETE FROM settings WHERE key = ?", key)
			if err := database.GetDB().Exec("INSERT INTO settings(key,value) VALUES (?,?)", key, value).Error; err != nil {
				t.Fatal(err)
			}
		}
	})
	p.start()
	ib := vlessInbound("mesh-control", inboundPort, nil, vlessClient("control-user"), vlessClient("control-other"))
	ib["listen"] = "127.0.0.1"
	p.call(http.MethodPost, "/panel/api/inbounds/add", ib)
	p.call(http.MethodPost, "/panel/api/server/stopXrayService", nil)
	p.stop()
	var owner, fingerprint string
	var authority ed25519.PrivateKey
	var config service.MeshConfig
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	withDB(func() {
		var err error
		owner, err = new(service.SettingService).GetPanelGuid()
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err = service.MeshAliasFingerprint(database.GetDB(), "control-user")
		if err != nil {
			t.Fatal(err)
		}
		authority, config = installTestMeshIdentity(t, p, owner, key)
	})
	p.start()
	t.Cleanup(func() { _, _ = p.try(http.MethodPost, "/panel/api/server/stopXrayService", nil) })
	_, trust, err := service.LoadMeshConfig(filepath.Join(p.dir, "db", "mesh", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	controlHTTP, _, err := quotaescrow.HTTPClients(trust, "")
	if err != nil {
		t.Fatal(err)
	}
	defer controlHTTP.CloseIdleConnections()
	plan := quotaescrow.ControlPlan{ID: "live-enroll", Subscription: "live/subscriber", Kind: "enroll", NextEpoch: "first", Claims: map[string][]quotaescrow.AliasClaim{owner: {{Email: "control-user", Fingerprint: fingerprint}}}}
	request := func(operation string, policy *quotaescrow.Policy, receipts []quotaescrow.ControlReceipt) quotaescrow.ControlReceipt {
		t.Helper()
		now := time.Now().Unix()
		signed, err := quotaescrow.SignControl(quotaescrow.ControlCommand{Plan: plan, Operation: operation, Policy: policy, Receipts: receipts, IssuedAt: now - 1, ValidUntil: now + 120}, authority)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		response, err := controlHTTP.Post(strings.TrimSuffix(config.Peers[owner], "/exchange")+"/control", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(response.Body)
			t.Fatalf("control %s/%s: %d %s", plan.Kind, operation, response.StatusCode, b)
		}
		var receipt quotaescrow.ControlReceipt
		if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
			t.Fatal(err)
		}
		if err := quotaescrow.VerifyControlReceipt(receipt, plan, pub); err != nil {
			t.Fatal(err)
		}
		return receipt
	}
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
			case <-time.After(10 * time.Millisecond):
			}
		}
	}))
	defer target.Close()
	client := quotaProxyClient(t, core, inboundPort, newUUID("control-user"))
	other := quotaProxyClient(t, core, inboundPort, newUUID("control-other"))
	otherResponse, err := other.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer otherResponse.Body.Close()
	var otherBytes quotaByteCounter
	go io.Copy(&otherBytes, otherResponse.Body)
	startStream := func() chan struct{} {
		t.Helper()
		var response *http.Response
		eventually(t, 8*time.Second, "controlled user admitted", func() (bool, string) {
			var err error
			response, err = client.Get(target.URL)
			if err != nil {
				return false, err.Error()
			}
			return true, ""
		})
		if _, err := io.ReadFull(response.Body, make([]byte, 32<<10)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { io.Copy(io.Discard, response.Body); response.Body.Close(); close(done) }()
		return done
	}
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1 << 30, Grants: map[string]int64{owner: 1 << 30}, Keys: map[string][]byte{owner: pub}}
	for _, kind := range []string{"enroll", "renew", "reset"} {
		if kind != "enroll" {
			plan.ID = "live-" + kind
			plan.Kind = kind
			plan.Epoch = policy.Epoch
			plan.NextEpoch = kind + "-epoch"
		}
		done := startStream()
		receipt := request("prepare", nil, nil)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("prepare acknowledged before stream ended")
		}
		before := otherBytes.bytes.Load()
		eventually(t, time.Second, "unrelated user survives lifecycle barrier", func() (bool, string) { return otherBytes.bytes.Load() > before, "no bytes" })
		policy.Epoch = plan.NextEpoch
		if kind == "enroll" {
			policy.AlreadyBilled = receipt.Local["control-user"]
		}
		if kind == "renew" {
			withDB(func() {
				ledger, err := quotaescrow.NewStore(database.GetDB()).Load(plan.Subscription)
				if err != nil {
					t.Fatal(err)
				}
				policy.AlreadyBilled, err = ledger.Billed()
				if err != nil {
					t.Fatal(err)
				}
			})
		}
		if kind == "reset" {
			policy.AlreadyBilled = 0
		}
		policy.Grants[owner] = policy.Limit - policy.AlreadyBilled
		request("commit", &policy, []quotaescrow.ControlReceipt{receipt})
		request("commit", &policy, []quotaescrow.ControlReceipt{receipt})
		withDB(func() {
			ledger, err := quotaescrow.NewStore(database.GetDB()).Load(plan.Subscription)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ledger.Billed()
			if err != nil || got != policy.AlreadyBilled {
				t.Fatalf("%s usage=%d want=%d err=%v", kind, got, policy.AlreadyBilled, err)
			}
		})
	}
}
