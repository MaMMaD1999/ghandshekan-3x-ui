package meshconsensus

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

type routeFilter struct {
	base    http.RoundTripper
	allowed func(string) bool
}

func (f routeFilter) RoundTrip(r *http.Request) (*http.Response, error) {
	if !f.allowed(r.URL.Host) {
		return nil, errors.New("simulated network partition")
	}
	return f.base.RoundTrip(r)
}

type wireGroup struct {
	wires   map[string]*Wire
	mu      sync.RWMutex
	links   map[string]bool
	clients []*http.Client
}

func (g *wireGroup) connect(edges ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.links = map[string]bool{}
	for _, e := range edges {
		g.links[e] = true
	}
}

func tlsFixture(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test control CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pair, pool
}
func wireCluster(t *testing.T) *wireGroup {
	t.Helper()
	pair, pool := tlsFixture(t)
	g := &wireGroup{wires: map[string]*Wire{}, links: map[string]bool{}}
	keys := map[string][]byte{}
	priv := map[string]ed25519.PrivateKey{}
	peers := map[string]string{}
	owners := map[string]string{}
	for _, id := range []string{"a", "b", "c"} {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		keys[id], priv[id] = pub, key
	}
	for _, id := range []string{"a", "b", "c"} {
		w := &Wire{Owner: id, Epoch: "wire-1", Keys: keys, Key: priv[id], Peers: peers, AttemptTimeout: 500 * time.Millisecond}
		g.wires[id] = w
		s := httptest.NewUnstartedServer(w)
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
		s.StartTLS()
		t.Cleanup(s.Close)
		peers[id] = s.URL + "/exchange"
		owners[s.Listener.Addr().String()] = id
	}
	for _, id := range []string{"a", "b", "c"} {
		base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}}
		t.Cleanup(base.CloseIdleConnections)
		client := &http.Client{Transport: routeFilter{base: base, allowed: func(host string) bool { g.mu.RLock(); defer g.mu.RUnlock(); return g.links[id+owners[host]] }}}
		g.wires[id].Direct = client
		g.clients = append(g.clients, &http.Client{Transport: base})
	}
	return g
}

func TestSignedControlUsesDirectThenPeerRelayThenExplicitEgress(t *testing.T) {
	g := wireCluster(t)
	for _, w := range g.wires {
		owner := w.Owner
		w.SetHandler(func(_ context.Context, from, kind string, b json.RawMessage) (any, error) {
			return map[string]string{"owner": owner, "from": from}, nil
		})
	}
	var fallback atomic.Int32
	g.wires["a"].Egress = func() (*http.Client, error) { fallback.Add(1); return g.clients[0], nil }
	call := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		var out map[string]string
		if err := g.wires["a"].Call(ctx, "c", "attest", map[string]string{"request": "test"}, &out); err != nil {
			t.Fatal(err)
		}
		if out["owner"] != "c" || out["from"] != "a" {
			t.Fatal("relay replaced the destination or original signer")
		}
	}
	g.connect("ac")
	call()
	if fallback.Load() != 0 {
		t.Fatal("direct request used egress")
	}
	g.connect("ab", "bc")
	call()
	if fallback.Load() != 0 {
		t.Fatal("relayed request used egress")
	}
	g.connect()
	call()
	if fallback.Load() != 1 {
		t.Fatal("explicit fallback did not run last")
	}
	// A foreign key cannot submit an apparently valid local operation.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	g.wires["a"].Key = wrong
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var out any
	if err := g.wires["a"].Call(ctx, "c", "propose", Command{ID: "attack"}, &out); err == nil {
		t.Fatal("unknown signer was accepted")
	}
}

func TestRaftOverAuthenticatedRelayTransport(t *testing.T) {
	g := wireCluster(t)
	g.connect("ab", "ba", "bc", "cb") // a and c have no direct route.
	_, authority, _ := ed25519.GenerateKey(rand.Reader)
	nodes := map[string]*Node{}
	for _, id := range []string{"a", "b", "c"} {
		wire := g.wires[id]
		tr := NewTransport(id)
		tr.Call = wire.Call
		cfg := raft.DefaultConfig()
		cfg.HeartbeatTimeout = time.Second
		cfg.ElectionTimeout = time.Second
		cfg.LeaderLeaseTimeout = time.Second
		cfg.CommitTimeout = 20 * time.Millisecond
		cfg.LogOutput = io.Discard
		n, err := Open(Options{Owner: id, Epoch: wire.Epoch, Keys: wire.Keys, Key: wire.Key, Authority: authority.Public().(ed25519.PublicKey), Directory: filepath.Join(t.TempDir(), id), Transport: tr, Bootstrap: true, Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		n.Call = wire.Call
		nodes[id] = n
		wire.SetHandler(func(ctx context.Context, from, kind string, b json.RawMessage) (any, error) {
			if kind == "attest" || kind == "propose" || kind == "submit" || kind == "admit" {
				return n.Handle(ctx, kind, b)
			}
			return tr.Handle(ctx, from, kind, b)
		})
		t.Cleanup(func() { n.Close(); _ = tr.Close() })
	}
	deadline := time.Now().Add(8 * time.Second)
	var leader *Node
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.Raft.State() == raft.Leader && n.Raft.VerifyLeader().Error() == nil {
				leader = n
				break
			}
		}
		if leader != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("relayed Raft did not elect a leader")
	}
	p := quotaescrow.Policy{Subscription: "wire-client", Epoch: "meter", Mode: "shared", Limit: 100, Version: 1, ResetGeneration: 1, Manager: "a", Authority: authority.Public().(ed25519.PublicKey), Keys: g.wires["a"].Keys, Grants: map[string]int64{"a": 0, "b": 0, "c": 0}, ControlEpoch: "wire-1", ControlKeys: g.wires["a"].Keys}
	reg, _ := SignRegistration(p, authority)
	execute(t, leader, Command{ID: "enroll", Registration: &reg})
	out := execute(t, nodes["a"], Command{ID: "via-relay", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{}})
	certified := certify(t, leader, p, *out.Update)
	if err := quotaescrow.VerifyPolicyUpdate(p, certified); err != nil {
		t.Fatal(err)
	}
}
