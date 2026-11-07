package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func TestMeshQuorumPanelResetWhileMasterOfflineAndRejoin(t *testing.T) {
	a, authority, plan, _ := controlFixture(t, "a")
	b, _, bp, _ := controlFixture(t, "b")
	c, _, cp, _ := controlFixture(t, "c")
	b.Authority, c.Authority = a.Authority, a.Authority
	plan.Claims["b"], plan.Claims["c"] = bp.Claims["b"], cp.Claims["c"]
	controls := map[string]*MeshControl{"a": a, "b": b, "c": c}
	keys := map[string][]byte{}
	for id, n := range controls {
		keys[id] = n.Key.Public().(ed25519.PublicKey)
	}
	nodes := map[string]*meshconsensus.Node{}
	transports := map[string]*raft.InmemTransport{}
	quorums := map[string]*MeshQuorum{}
	var mu sync.RWMutex
	offline := false
	for _, id := range []string{"a", "b", "c"} {
		_, tr := raft.NewInmemTransportWithTimeout(raft.ServerAddress(id), 100*time.Millisecond)
		cfg := raft.DefaultConfig()
		cfg.HeartbeatTimeout = 150 * time.Millisecond
		cfg.ElectionTimeout = 150 * time.Millisecond
		cfg.LeaderLeaseTimeout = 100 * time.Millisecond
		cfg.CommitTimeout = 10 * time.Millisecond
		cfg.LogOutput = io.Discard
		n, err := meshconsensus.Open(meshconsensus.Options{Owner: id, Epoch: "control-1", Keys: keys, Key: controls[id].Key, Authority: a.Authority, Directory: filepath.Join(t.TempDir(), id), Transport: tr, Bootstrap: true, Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		nodes[id], transports[id] = n, tr
		quorums[id] = &MeshQuorum{Node: n, Local: controls[id], certificates: map[string]quotaescrow.PolicyUpdate{}}
		n.Call = func(ctx context.Context, to, kind string, in, out any) error {
			mu.RLock()
			blocked := offline && (id == "a" || to == "a")
			target := nodes[to]
			mu.RUnlock()
			if blocked {
				return errors.New("master partition")
			}
			body, _ := json.Marshal(in)
			value, err := target.Handle(ctx, kind, body)
			if err != nil {
				return err
			}
			body, _ = json.Marshal(value)
			return json.Unmarshal(body, out)
		}
		t.Cleanup(func() { n.Close(); _ = tr.Close() })
	}
	connect := func() {
		for id, tr := range transports {
			for to, target := range transports {
				if id != to {
					tr.Connect(raft.ServerAddress(to), target)
				}
			}
		}
	}
	connect()
	leader := func(ids ...string) *meshconsensus.Node {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			for _, id := range ids {
				n := nodes[id]
				if n.Raft.State() == raft.Leader && n.Raft.VerifyLeader().Error() == nil {
					return n
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("no control leader")
		return nil
	}
	current := leader("a", "b", "c")
	if err := a.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	coordinator := quotaescrow.Coordinator{Owner: "a", DB: a.DB, Authority: authority, ControlEpoch: "control-1", ControlKeys: keys, InitialUsage: func(context.Context, quotaescrow.ControlPlan, []quotaescrow.ControlReceipt) (int64, error) {
		return 100, nil
	}, Call: func(ctx context.Context, owner string, s quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		return controls[owner].Execute(ctx, s)
	}}
	coordinator.RegisterPolicy = func(ctx context.Context, p quotaescrow.Policy) error {
		r, e := meshconsensus.SignRegistration(p, authority)
		if e != nil {
			return e
		}
		_, e = current.Execute(ctx, meshconsensus.Command{ID: "enroll", Registration: &r})
		return e
	}
	if err := coordinator.Create(plan, nil, quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: 1000}, keys); err != nil {
		t.Fatal(err)
	}
	if _, done, err := coordinator.Resume(context.Background(), plan.ID); err != nil || !done {
		t.Fatal("enrollment", done, err)
	}
	// Let all followers apply enrollment before isolating the manager.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, eb := nodes["b"].FSM.Policy(plan.Subscription)
		_, ec := nodes["c"].FSM.Policy(plan.Subscription)
		if eb == nil && ec == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	offline = true
	mu.Unlock()
	transports["a"].DisconnectAll()
	transports["b"].Disconnect("a")
	transports["c"].Disconnect("a")
	current = leader("b", "c")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_, err := quorums["a"].Queue(ctx, plan.Subscription, "renew", "isolated", nil, nil)
	cancel()
	if err == nil {
		t.Fatal("isolated manager changed the subscription")
	}
	// Any admin in the connected majority can submit, even if it isn't leader.
	admin := &MeshAdministrator{Local: b, Quorum: quorums["b"]}
	if _, err := admin.Queue(context.Background(), plan.Subscription, "reset", "request-once", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := quorums["c"].SyncCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 17, 0) }); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Queue(context.Background(), plan.Subscription, "reset", "request-once", nil, nil); err != nil {
		t.Fatal("idempotent retry", err)
	}
	limit := int64(2000)
	if _, err := admin.Queue(context.Background(), plan.Subscription, "renew", "renew-main", &limit, nil); err != nil {
		t.Fatal(err)
	}
	l, err := quotaescrow.NewStore(b.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := l.Billed(); used != 17 {
		t.Fatal("renew or retried reset lost new usage", used)
	}
	if l.Policy().ResetGeneration != 2 || l.Policy().Version != 3 {
		t.Fatal("wrong policy cycle")
	}
	mu.Lock()
	offline = false
	mu.Unlock()
	connect()
	leader("a", "b", "c")
	bounded, release := context.WithTimeout(context.Background(), 3*time.Second)
	defer release()
	if err := quorums["a"].synchronize(bounded, plan.Subscription, 3); err != nil {
		t.Fatal(err)
	}
	caught, err := quotaescrow.NewStore(a.DB).Load(plan.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	if caught.Policy().Version != 3 || caught.Policy().Limit != 2000 {
		t.Fatal("master did not learn majority update")
	}
	if err := caught.Merge(l.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if used, _ := caught.Billed(); used != 17 {
		t.Fatal("catchup duplicated or lost actual usage", used)
	}
}
