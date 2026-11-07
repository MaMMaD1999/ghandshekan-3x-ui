package nodee2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"github.com/mhsanaei/3x-ui/v3/internal/xray/meshgate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func installTestMeshIdentity(t *testing.T, p *panel, owner string, key ed25519.PrivateKey) (ed25519.PrivateKey, service.MeshConfig) {
	t.Helper()
	dir := filepath.Join(p.dir, "db", "mesh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test mesh"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: der}, "cert.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "PRIVATE KEY", Bytes: encoded}} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	authority, authorityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	address := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	c := service.MeshConfig{Owner: owner, PrivateKey: key, Authority: authority, Listen: address, CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), CAFile: filepath.Join(dir, "ca.pem"), StateDir: filepath.Join(dir, "state"), Peers: map[string]string{owner: "https://" + address + "/exchange", "offline-master": fmt.Sprintf("https://127.0.0.1:%d/exchange", freePort(t))}}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return authorityPrivate, c
}

// The peer endpoint is unreachable throughout. This uses the installed panel
// supervisor and scheduled meter, never calls the runtime gate from the test.
func TestMeshRuntimeCutsRealStreamWithMasterOffline(t *testing.T) {
	testMeshRuntimeOfflineCutoff(t, "")
}

func TestMeshSharedQuotaCutsRealStreamWithMasterOffline(t *testing.T) {
	testMeshRuntimeOfflineCutoff(t, "shared")
}

func testMeshRuntimeOfflineCutoff(t *testing.T, mode string) {
	core := os.Getenv("MESH_TEST_CORE")
	if core == "" {
		t.Skip("MESH_TEST_CORE not set")
	}
	p := newPanel(t, panelBinary(t), "mesh-offline")
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
	limited, other := vlessClient("mesh-limited"), vlessClient("legacy-other")
	ib := vlessInbound("mesh-test", inboundPort, nil, limited, other)
	ib["listen"] = "127.0.0.1"
	p.call(http.MethodPost, "/panel/api/inbounds/add", ib)
	p.call(http.MethodPost, "/panel/api/server/stopXrayService", nil)
	p.stop()
	var localOwner string
	var remoteKey ed25519.PrivateKey
	withDB(func() {
		owner, err := new(service.SettingService).GetPanelGuid()
		if err != nil {
			t.Fatal(err)
		}
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		remote, remotePrivate, _ := ed25519.GenerateKey(rand.Reader)
		localOwner, remoteKey = owner, remotePrivate
		policy := quotaescrow.Policy{Subscription: "mesh-sub", Epoch: "one", Limit: 128 << 20, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{owner: 1 << 20, "offline-master": 127 << 20}, Keys: map[string][]byte{owner: pub, "offline-master": remote}}
		if mode == "shared" {
			policy.Mode = mode
			policy.Limit = 1 << 20
			policy.Grants[owner], policy.Grants["offline-master"] = 0, 0
		}
		if err := service.ActivateMeshMeters(database.GetDB(), policy, owner, []string{"mesh-limited"}); err != nil {
			t.Fatal(err)
		}
		installTestMeshIdentity(t, p, owner, key)
		cfg, _, err := service.LoadMeshConfig(filepath.Join(p.dir, "db", "mesh", "identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		checkpoint, err := service.OpenMeshCheckpoint(database.GetDB(), cfg, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkpoint.Close(); err != nil {
			t.Fatal(err)
		}
	})
	p.start()
	t.Cleanup(func() { _, _ = p.try(http.MethodPost, "/panel/api/server/stopXrayService", nil) })
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state := func() *meshgate.State {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r := new(meshgate.State)
		if err := conn.Invoke(ctx, "/xray.app.stats.command.StatsService/GetUserGates", &meshgate.GetRequest{Scope: "mesh"}, r); err != nil {
			t.Fatal(err)
		}
		return r
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
			case <-time.After(5 * time.Millisecond):
			}
		}
	}))
	defer target.Close()
	limitedHTTP := quotaProxyClient(t, core, inboundPort, newUUID("mesh-limited"))
	otherHTTP := quotaProxyClient(t, core, inboundPort, newUUID("legacy-other"))
	otherStream, err := otherHTTP.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStream.Body.Close()
	var otherBytes quotaByteCounter
	otherDone := make(chan error, 1)
	go func() { _, err := io.Copy(&otherBytes, otherStream.Body); otherDone <- err }()
	// Wait for cold-start fence acknowledgement and hot admission of this alias.
	var response *http.Response
	eventually(t, 8*time.Second, "mesh client admitted after startup", func() (bool, string) {
		var e error
		response, e = limitedHTTP.Get(target.URL)
		if e != nil {
			return false, e.Error()
		}
		return true, ""
	})
	defer response.Body.Close()
	before := state().Instance
	if _, err := io.ReadFull(response.Body, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); close(done) }()
	select {
	case <-done:
	case <-time.After(18 * time.Second):
		t.Fatal("offline mesh failed to cut exhausted stream")
	}
	if state().Instance != before {
		t.Fatal("mesh cutoff restarted entire core")
	}
	stored, found := p.inboundOnPort(inboundPort)
	if !found || stored.client("mesh-limited")["enable"] != true {
		t.Fatal("local escrow cutoff mutated master-owned enable flag")
	}
	baseline := otherBytes.bytes.Load()
	eventually(t, 2*time.Second, "unrelated stream survives mesh cutoff", func() (bool, string) {
		select {
		case err := <-otherDone:
			t.Fatalf("unrelated stream stopped: %v", err)
		default:
		}
		return otherBytes.bytes.Load() > baseline, "no bytes"
	})
	if mode == "shared" {
		withDB(func() {
			ledger, err := quotaescrow.NewStore(database.GetDB()).Load("mesh-sub")
			if err != nil {
				t.Fatal(err)
			}
			billed, err := ledger.Billed()
			if err != nil || billed < 1<<20 {
				t.Fatal("shared cutoff did not retain real metered traffic", billed, err)
			}
			remaining, err := ledger.Available(localOwner, time.Now().Unix())
			if err != nil || remaining != 0 {
				t.Fatal("shared quota remained open", remaining, err)
			}
		})
		return
	}
	// A config refresh while exhausted can remove credentials from the core.
	// Receiving legitimate peer credit must restore them without a whole restart.
	p.call(http.MethodPost, "/panel/api/server/reconcileXrayService", nil)
	withDB(func() {
		store := quotaescrow.NewStore(database.GetDB())
		ledger, err := store.Load("mesh-sub")
		if err != nil {
			t.Fatal(err)
		}
		billedBefore, _ := ledger.Billed()
		// Polling overrun is real usage and remains debt. Provide enough rights
		// to cover it; a transfer must not erase or add to that billed usage.
		_, err = store.Transfer("mesh-sub", "offline-master", remoteKey, 127<<20, localOwner, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		ledger, err = store.Load("mesh-sub")
		if err != nil {
			t.Fatal(err)
		}
		billedAfter, _ := ledger.Billed()
		if billedBefore != billedAfter {
			t.Fatal("transfer was charged as traffic")
		}
	})
	eventually(t, 8*time.Second, "transferred credit restores filtered client", func() (bool, string) {
		response, err := limitedHTTP.Get(target.URL)
		if err != nil {
			return false, err.Error()
		}
		defer response.Body.Close()
		_, err = io.ReadFull(response.Body, make([]byte, 1024))
		return err == nil, fmt.Sprint(err)
	})
	if state().Instance != before {
		t.Fatal("credit transfer restarted entire core")
	}
}
