package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func meshRuntimeFixture(t *testing.T, owner string) (string, *MeshConfig) {
	t.Helper()
	dir := t.TempDir()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mesh test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: caDER}, "cert.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "PRIVATE KEY", Bytes: pk}} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	authority, _, _ := ed25519.GenerateKey(rand.Reader)
	_, usageKey, _ := ed25519.GenerateKey(rand.Reader)
	c := &MeshConfig{Owner: owner, PrivateKey: usageKey, Authority: authority, Listen: address, CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), CAFile: filepath.Join(dir, "ca.pem"), StateDir: filepath.Join(dir, "state"), Peers: map[string]string{owner: "https://" + address + "/exchange"}}
	encoded, _ := json.Marshal(c)
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path, c
}

func TestMeshRuntimeMutualTLSAndStop(t *testing.T) {
	setupConflictDB(t)
	owner, err := new(SettingService).GetPanelGuid()
	if err != nil {
		t.Fatal(err)
	}
	path, c := meshRuntimeFixture(t, owner)
	t.Setenv("XUI_MESH_CONFIG", path)
	_, trust, err := LoadMeshConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := StartMeshRuntime(context.Background(), new(XrayService))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Stop(); meshGuardEnabled.Store(false); meshAdmissionReady.Store(false) })
	client, _, err := quotaescrow.HTTPClients(trust, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get(c.Peers[owner])
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected exchange response %d", resp.StatusCode)
	}
	without := trust.Clone()
	without.Certificates = nil
	unauth := &http.Client{Transport: &http.Transport{TLSClientConfig: without}, Timeout: time.Second}
	defer unauth.CloseIdleConnections()
	if resp, err := unauth.Get(c.Peers[owner]); err == nil {
		resp.Body.Close()
		t.Fatal("peer without certificate admitted")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Get(c.Peers[owner]); err == nil {
		resp.Body.Close()
		t.Fatal("mesh listener still live after Stop")
	}
}

func TestMeshConfigRejectsMisboundIdentityAndUnknownFields(t *testing.T) {
	path, c := meshRuntimeFixture(t, "owner")
	if _, _, err := LoadMeshConfig(path); err != nil {
		t.Fatal(err)
	}
	c.Peers[c.Owner] = "https://wrong.example/exchange"
	b, _ := json.Marshal(c)
	os.WriteFile(path, b, 0600)
	if _, _, err := LoadMeshConfig(path); err == nil {
		t.Fatal("certificate endpoint mismatch accepted")
	}
	c.Peers[c.Owner] = "https://127.0.0.1/exchange"
	b, _ = json.Marshal(c)
	b = append(b[:len(b)-1], []byte(`,"unexpected":true}`)...)
	os.WriteFile(path, b, 0600)
	if _, _, err := LoadMeshConfig(path); err == nil {
		t.Fatal("unknown identity field accepted")
	}
	c.PrivateKey[63] ^= 1
	if err := c.validate(); err == nil {
		t.Fatal("corrupt private key accepted")
	}
}

func TestMeshColdStartAndReadinessFenceOnlyManagedAliases(t *testing.T) {
	setupConflictDB(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := quotaescrow.Policy{Subscription: "sub", Epoch: "one", Limit: 100, ExpiresAt: time.Now().Unix() + 3600, Grants: map[string]int64{"local": 100}, Keys: map[string][]byte{"local": pub}}
	if err := ActivateMeshMeters(database.GetDB(), p, "local", []string{"managed"}); err != nil {
		t.Fatal(err)
	}
	BeginMeshRuntime()
	t.Cleanup(func() { meshGuardEnabled.Store(false); meshAdmissionReady.Store(false) })
	if ok, err := MeshClientAllowed("managed"); err != nil || ok {
		t.Fatal(ok, err)
	}
	if ok, err := MeshClientAllowed("legacy"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	meshAdmissionReady.Store(true)
	if ok, err := MeshClientAllowed("managed"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{{Tag: "no-settings"}, {Tag: "users", Settings: []byte(`{"clients":[{"email":"managed"},{"email":"legacy"}]}`)}}}
	if err := fenceMeshColdConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if meshCanAdmit() || strings.Contains(string(cfg.InboundConfigs[1].Settings), "managed") || !strings.Contains(string(cfg.InboundConfigs[1].Settings), "legacy") {
		t.Fatal("cold start failed to fence managed users only")
	}
}
