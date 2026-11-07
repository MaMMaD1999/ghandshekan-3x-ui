package nodee2e

import (
	"bytes"
	"context"
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
	testMeshControlRealLifecycle(t, false, false)
}

func TestMeshSharedRealLifecycleWhileDownloading(t *testing.T) {
	testMeshControlRealLifecycle(t, true, false)
}

// Consensus authorization is exercised separately by the multi-member tests.
// This test supplies majority-signed policies to the actual runtime and checks
// that device revocation terminates a live stream, not just future connections.
func TestMeshDeviceAttachRevokeRealStream(t *testing.T) {
	testMeshControlRealLifecycle(t, true, true)
}

func testMeshControlRealLifecycle(t *testing.T, shared, devices bool) {
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
	if devices {
		tablet := vlessClient("control-tablet")
		tablet["enable"] = false
		ib = vlessInbound("mesh-control", inboundPort, nil, vlessClient("control-user"), vlessClient("control-other"), tablet)
	}
	ib["listen"] = "127.0.0.1"
	p.call(http.MethodPost, "/panel/api/inbounds/add", ib)
	p.call(http.MethodPost, "/panel/api/server/stopXrayService", nil)
	p.stop()
	var owner, fingerprint, tabletFingerprint string
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
		if devices {
			tabletFingerprint, err = service.MeshAliasFingerprint(database.GetDB(), "control-tablet")
			if err != nil {
				t.Fatal(err)
			}
		}
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
	now := time.Now().Unix()
	inspection, err := quotaescrow.SignInspection(quotaescrow.Inspection{Owner: owner, Nonce: rand.Text(), Emails: []string{"control-user"}, IssuedAt: now - 1, ValidUntil: now + 60}, authority)
	if err != nil {
		t.Fatal(err)
	}
	privateClient := quotaescrow.ControlClient{HTTP: controlHTTP, Peers: config.Peers, Keys: map[string][]byte{owner: pub}}
	inventory, err := privateClient.Inspect(context.Background(), owner, inspection)
	if err != nil || len(inventory.Aliases) != 1 || inventory.Aliases[0].Claim.Fingerprint != fingerprint {
		t.Fatal("real private inspection failed", err)
	}
	plan.Claims[owner] = []quotaescrow.AliasClaim{inventory.Aliases[0].Claim}
	plan.AccountingRoots = []quotaescrow.LegacyRoot{{Owner: owner, Alias: "control-user"}}
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
	if shared {
		policy.Mode = "shared"
		policy.Version = 1
		policy.ResetGeneration = 1
		policy.Authority = config.Authority
		policy.Manager = owner
		policy.Grants[owner] = 0
	}
	var updates []quotaescrow.PolicyUpdate
	kinds := []string{"enroll", "renew", "reset"}
	voters := map[string]ed25519.PrivateKey{owner: key}
	if devices {
		policy.ControlEpoch = "device-runtime-test"
		policy.ControlKeys = map[string][]byte{owner: pub}
		for _, id := range []string{"voter-b", "voter-c"} {
			public, private, _ := ed25519.GenerateKey(rand.Reader)
			policy.ControlKeys[id], voters[id] = public, private
		}
		policy.Aliases = quotaescrow.AliasCatalog{owner: {"control-user": {Fingerprint: fingerprint, Revision: 1}}}
		kinds = []string{"enroll"}
	}
	for _, kind := range kinds {
		if shared && kind != "enroll" {
			done := startStream()
			u, err := quotaescrow.SignPolicyUpdate(policy, "real-shared-"+kind, kind, policy.Limit, policy.ExpiresAt, authority)
			if err != nil {
				t.Fatal(err)
			}
			updates = append(updates, u)
			if _, err := privateClient.UpdatePolicy(context.Background(), owner, quotaescrow.PolicyUpdateRequest{Subscription: policy.Subscription, Updates: updates}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("shared lifecycle acknowledged before stream drained")
			}
			policy = u.Next
			before := otherBytes.bytes.Load()
			eventually(t, time.Second, "unrelated user survives shared update", func() (bool, string) { return otherBytes.bytes.Load() > before, "no bytes" })
			withDB(func() {
				l, err := quotaescrow.NewStore(database.GetDB()).Load(plan.Subscription)
				if err != nil {
					t.Fatal(err)
				}
				used, err := l.Billed()
				if err != nil {
					t.Fatal(err)
				}
				if kind == "reset" && used != 0 {
					t.Fatal("reset retained old usage", used)
				}
				if kind == "renew" && used <= policy.AlreadyBilled {
					t.Fatal("renewal lost drained traffic", used)
				}
			})
			if _, err := privateClient.UpdatePolicy(context.Background(), owner, quotaescrow.PolicyUpdateRequest{Subscription: policy.Subscription, Updates: updates}); err != nil {
				t.Fatal("shared replay", err)
			}
			continue
		}
		if kind != "enroll" {
			plan.AccountingRoots = nil
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
			policy.AlreadyBilled, err = quotaescrow.PreparedHistoricalUsage(plan, []quotaescrow.ControlReceipt{receipt})
			if err != nil {
				t.Fatal(err)
			}
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
		if shared {
			policy.Grants[owner] = 0
		}
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
	if !devices {
		return
	}
	applyDevicePolicy := func(update quotaescrow.PolicyUpdate) {
		t.Helper()
		update.Votes = map[string][]byte{}
		for _, id := range []string{owner, "voter-b"} {
			update.Votes[id] = quotaescrow.PolicyUpdateVote(update, voters[id])
		}
		if _, err := privateClient.UpdatePolicy(context.Background(), owner, quotaescrow.PolicyUpdateRequest{Subscription: policy.Subscription, Updates: []quotaescrow.PolicyUpdate{update}}); err != nil {
			t.Fatal(err)
		}
		policy = update.Next
	}
	add, err := quotaescrow.DraftAliasChange(policy, "attach-tablet", quotaescrow.AliasPatch{Owner: owner, Email: "control-tablet", Fingerprint: tabletFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	applyDevicePolicy(add)
	tablet := quotaProxyClient(t, core, inboundPort, newUUID("control-tablet"))
	var response *http.Response
	eventually(t, 8*time.Second, "new device admitted", func() (bool, string) {
		var err error
		response, err = tablet.Get(target.URL)
		return err == nil, fmt.Sprint(err)
	})
	if _, err := io.ReadFull(response.Body, make([]byte, 32<<10)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); response.Body.Close(); close(done) }()
	revoke, err := quotaescrow.DraftAliasChange(policy, "revoke-tablet", quotaescrow.AliasPatch{Owner: owner, Email: "control-tablet", Fingerprint: tabletFingerprint, ExpectedRevision: 1, Revoked: true})
	if err != nil {
		t.Fatal(err)
	}
	applyDevicePolicy(revoke)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked device's existing download survived")
	}
	var usedAfterRevoke int64
	withDB(func() {
		ledger, err := quotaescrow.NewStore(database.GetDB()).Load(policy.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		usedAfterRevoke, err = ledger.Billed()
		if err != nil || usedAfterRevoke <= policy.AlreadyBilled {
			t.Fatal("revocation lost drained device traffic", usedAfterRevoke, err)
		}
	})
	renew, err := quotaescrow.DraftPolicyChange(policy, "renew-after-device-revoke", "renew", quotaescrow.ControlTarget{Limit: 2 << 30})
	if err != nil {
		t.Fatal(err)
	}
	applyDevicePolicy(renew)
	// Replay a valid older attach certificate after revocation and renewal.
	add.Votes = map[string][]byte{}
	for _, id := range []string{owner, "voter-b"} {
		add.Votes[id] = quotaescrow.PolicyUpdateVote(add, voters[id])
	}
	_, _ = privateClient.UpdatePolicy(context.Background(), owner, quotaescrow.PolicyUpdateRequest{Subscription: policy.Subscription, Updates: []quotaescrow.PolicyUpdate{add}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if r, err := tablet.Do(req); err == nil {
		r.Body.Close()
		t.Fatal("renewal or delayed attach resurrected revoked device")
	}
	withDB(func() {
		ledger, err := quotaescrow.NewStore(database.GetDB()).Load(policy.Subscription)
		if err != nil {
			t.Fatal(err)
		}
		used, err := ledger.Billed()
		if err != nil || used != usedAfterRevoke || !ledger.Policy().Aliases[owner]["control-tablet"].Revoked {
			t.Fatal("renewal/replay altered stopped device consumption", used, usedAfterRevoke, err)
		}
	})
	before := otherBytes.bytes.Load()
	eventually(t, time.Second, "unrelated stream survives device changes", func() (bool, string) { return otherBytes.bytes.Load() > before, "no bytes" })
}
