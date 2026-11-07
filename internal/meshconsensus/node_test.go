package meshconsensus

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

type testCluster struct {
	t          *testing.T
	root       string
	keys       map[string][]byte
	private    map[string]ed25519.PrivateKey
	authority  ed25519.PrivateKey
	nodes      map[string]*Node
	transports map[string]*raft.InmemTransport
	mu         sync.RWMutex
	links      map[string]bool
}

func cluster(t *testing.T, count int) *testCluster {
	t.Helper()
	_, authority, _ := ed25519.GenerateKey(rand.Reader)
	c := &testCluster{t: t, root: t.TempDir(), keys: map[string][]byte{}, private: map[string]ed25519.PrivateKey{}, authority: authority, nodes: map[string]*Node{}, transports: map[string]*raft.InmemTransport{}, links: map[string]bool{}}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("node-%02d", i)
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		c.keys[id] = pub
		c.private[id] = key
	}
	for id := range c.keys {
		c.start(id, true)
	}
	ids := c.ids()
	c.partition(ids)
	t.Cleanup(func() {
		for _, n := range c.nodes {
			n.Close()
		}
		for _, tr := range c.transports {
			_ = tr.Close()
		}
	})
	return c
}
func (c *testCluster) ids() []string {
	var out []string
	for id := range c.keys {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
func (c *testCluster) start(id string, bootstrap bool) {
	_, tr := raft.NewInmemTransportWithTimeout(raft.ServerAddress(id), 100*time.Millisecond)
	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 120 * time.Millisecond
	config.ElectionTimeout = 120 * time.Millisecond
	config.LeaderLeaseTimeout = 100 * time.Millisecond
	config.CommitTimeout = 5 * time.Millisecond
	config.LogOutput = io.Discard
	config.SnapshotThreshold = 16
	n, err := Open(Options{Owner: id, Epoch: "operator-generation-1", Directory: filepath.Join(c.root, id), Keys: c.keys, Key: c.private[id], Authority: c.authority.Public().(ed25519.PublicKey), Transport: tr, Bootstrap: bootstrap, Config: config})
	if err != nil {
		c.t.Fatal(err)
	}
	c.nodes[id], c.transports[id] = n, tr
	n.Call = func(ctx context.Context, to, kind string, in, out any) error {
		c.mu.RLock()
		link := c.links[id+"/"+to]
		target := c.nodes[to]
		c.mu.RUnlock()
		if !link {
			return fmt.Errorf("partition %s -> %s", id, to)
		}
		b, _ := json.Marshal(in)
		v, err := target.Handle(ctx, kind, b)
		if err != nil {
			return err
		}
		b, _ = json.Marshal(v)
		return json.Unmarshal(b, out)
	}
}
func (c *testCluster) partition(groups ...[]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.links = map[string]bool{}
	for _, tr := range c.transports {
		tr.DisconnectAll()
	}
	for _, group := range groups {
		for _, a := range group {
			for _, b := range group {
				if a != b {
					c.transports[a].Connect(raft.ServerAddress(b), c.transports[b])
					c.links[a+"/"+b] = true
				}
			}
		}
	}
}
func (c *testCluster) leader(ids []string) *Node {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, id := range ids {
			n := c.nodes[id]
			if n.Raft.State() == raft.Leader && n.Raft.VerifyLeader().Error() == nil {
				return n
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	c.t.Fatal("no majority leader")
	return nil
}
func (c *testCluster) base() quotaescrow.Policy {
	p := quotaescrow.Policy{Subscription: "subscriber", Epoch: "lifetime-1", Mode: "shared", Limit: 10000, Version: 1, ResetGeneration: 1, Keys: c.keys, Grants: map[string]int64{}, Manager: c.ids()[0], Authority: c.authority.Public().(ed25519.PublicKey), ControlEpoch: "operator-generation-1", ControlKeys: c.keys}
	for id := range c.keys {
		p.Grants[id] = 0
	}
	return p
}
func command(p quotaescrow.Policy, id, kind string, limit int64) Command {
	return Command{ID: id, Subscription: p.Subscription, Kind: kind, ExpectedHash: quotaescrow.PolicyHash(p), Target: quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: limit}}
}
func execute(t *testing.T, n *Node, c Command) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := n.Execute(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func certify(t *testing.T, n *Node, p quotaescrow.Policy, u quotaescrow.PolicyUpdate) quotaescrow.PolicyUpdate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, e := n.Certify(ctx, p, u)
	if e != nil {
		t.Fatal(e)
	}
	return out
}

func TestMajorityContinuesWithoutMasterAndRejectsIsolatedRenewal(t *testing.T) {
	for _, count := range []int{5, 10} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c := cluster(t, count)
			ids := c.ids()
			leader := c.leader(ids)
			p := c.base()
			reg, e := SignRegistration(p, c.authority)
			if e != nil {
				t.Fatal(e)
			}
			execute(t, leader, Command{ID: "register", Registration: &reg})
			initial := execute(t, leader, command(p, "first-renewal", "renew", 11000))
			first := certify(t, leader, p, *initial.Update)
			if e := quotaescrow.VerifyPolicyUpdate(p, first); e != nil {
				t.Fatal(e)
			}
			// Remove the old leader (and the configured master) from the main group.
			minority := []string{leader.Owner}
			if p.Manager != leader.Owner {
				minority = append(minority, p.Manager)
			}
			var main []string
			for _, id := range ids {
				if !slices.Contains(minority, id) {
					main = append(main, id)
				}
			}
			for len(main) > count/2+1 {
				minority = append(minority, main[len(main)-1])
				main = main[:len(main)-1]
			}
			// Every minority member is isolated, not a second decision-making group.
			groups := [][]string{main}
			for _, id := range minority {
				groups = append(groups, []string{id})
			}
			c.partition(groups...)
			active := c.leader(main)
			isolated := c.nodes[minority[0]]
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			_, err := isolated.Execute(ctx, command(first.Next, "isolated-renewal", "renew", 999999))
			cancel()
			if err == nil {
				t.Fatal("isolated node renewed subscription")
			}
			result := execute(t, active, command(first.Next, "main-reset", "reset", 12000))
			reset := certify(t, active, first.Next, *result.Update)
			if reset.Next.Version != 3 || reset.Next.ResetGeneration != 2 {
				t.Fatal("wrong lifecycle advancement")
			}
			if _, err := quotaescrow.SignPolicyChange(reset.Next, "root-bypass", "renew", quotaescrow.ControlTarget{Limit: 999999}, c.authority); err == nil {
				t.Fatal("root key bypassed majority")
			}
			// A fabricated future change cannot get even one honest committed vote.
			draft, _ := quotaescrow.DraftPolicyChange(reset.Next, "fake", "renew", quotaescrow.ControlTarget{Limit: 888888})
			if _, err := isolated.Attest(draft); err == nil {
				t.Fatal("isolated node attested an uncommitted value")
			}
			c.partition(ids)
			active = c.leader(ids)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				all := true
				for _, n := range c.nodes {
					v, e := n.FSM.Policy(p.Subscription)
					if e != nil || quotaescrow.PolicyHash(v) != quotaescrow.PolicyHash(reset.Next) {
						all = false
					}
				}
				if all {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			for _, n := range c.nodes {
				v, e := n.FSM.Policy(p.Subscription)
				if e != nil || quotaescrow.PolicyHash(v) != quotaescrow.PolicyHash(reset.Next) {
					t.Fatal("rejoining member changed the majority decision")
				}
			}
			// Retrying a committed reset through another leader returns that exact
			// version, never another reset of traffic accumulated after reconnecting.
			replay := execute(t, active, command(first.Next, "main-reset", "reset", 12000))
			if !quotaescrow.SamePolicyUpdate(*replay.Update, reset) {
				t.Fatal("reset replay created another cycle")
			}
			wrong := command(reset.Next, "main-reset", "reset", 13000)
			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			_, err = active.Execute(ctx, wrong)
			cancel()
			if err == nil {
				t.Fatal("reused ID accepted altered target")
			}
		})
	}
}

func TestCommittedPoliciesSurviveSnapshotAndFullClusterRestart(t *testing.T) {
	c := cluster(t, 3)
	ids := c.ids()
	leader := c.leader(ids)
	p := c.base()
	reg, _ := SignRegistration(p, c.authority)
	execute(t, leader, Command{ID: "register", Registration: &reg})
	request := command(p, "reset-once", "reset", 20000)
	out := execute(t, leader, request)
	certify(t, leader, p, *out.Update)
	for _, n := range c.nodes {
		if err := n.Raft.Snapshot().Error(); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range c.nodes {
		n.Close()
	}
	for _, tr := range c.transports {
		_ = tr.Close()
	}
	for _, id := range ids {
		c.start(id, false)
	}
	c.partition(ids)
	leader = c.leader(ids)
	replay := execute(t, leader, request)
	if replay.Update.Next.Version != 2 || replay.Update.Next.ResetGeneration != 2 {
		t.Fatal("restart replayed reset")
	}
	certify(t, leader, p, *replay.Update)
	// Losing a state directory must not silently form a fresh cluster.
	isolated := ids[0]
	c.nodes[isolated].Close()
	_ = c.transports[isolated].Close()
	if err := os.RemoveAll(filepath.Join(c.root, isolated)); err != nil {
		t.Fatal(err)
	}
	_, tr := raft.NewInmemTransport(raft.ServerAddress(isolated))
	defer tr.Close()
	_, err := Open(Options{Owner: isolated, Epoch: "operator-generation-1", Directory: filepath.Join(c.root, isolated), Keys: c.keys, Key: c.private[isolated], Authority: c.authority.Public().(ed25519.PublicKey), Transport: tr, Bootstrap: true})
	if err == nil {
		t.Fatal("lost state re-bootstrapped automatically")
	}
}

func TestJustIsolatedLeaderDoesNotQueueRenewalForLater(t *testing.T) {
	c := cluster(t, 3)
	ids := c.ids()
	leader := c.leader(ids)
	p := c.base()
	reg, _ := SignRegistration(p, c.authority)
	execute(t, leader, Command{ID: "register", Registration: &reg})
	var others []string
	for _, id := range ids {
		if id != leader.Owner {
			others = append(others, id)
		}
	}
	c.partition([]string{leader.Owner}, others)
	// Immediately after a link breaks, the old leader can still believe its
	// lease is valid. A failed renewal must not be appended for later replay.
	before := leader.Raft.LastIndex()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err := leader.Execute(ctx, command(p, "isolated-before-stepdown", "renew", 999999))
	cancel()
	if err == nil {
		t.Fatal("isolated leader accepted renewal")
	}
	if after := leader.Raft.LastIndex(); after != before {
		t.Fatalf("isolated renewal queued for later: log index %d -> %d", before, after)
	}
	c.partition(ids)
	active := c.leader(ids)
	if err := active.Raft.Barrier(time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	got, err := active.FSM.Policy(p.Subscription)
	if err != nil || got.Version != 1 || got.Limit != p.Limit {
		t.Fatal("failed isolated renewal became effective after reconnect")
	}
}

func TestAdmissionRejectsResponseFromAnEarlierRequest(t *testing.T) {
	c := cluster(t, 3)
	leader := c.leader(c.ids())
	p := c.base()
	reg, _ := SignRegistration(p, c.authority)
	blocked := command(p, "stale-admission", "renew", 20000)
	call := leader.Call
	leader.Call = func(ctx context.Context, to, kind string, in, out any) error {
		if err := call(ctx, to, kind, in, out); err != nil {
			return err
		}
		if kind == "admit" && in.(admission).CommandHash == digest(blocked) {
			out.(*admission).Nonce = "earlier-request"
		}
		return nil
	}
	execute(t, leader, Command{ID: "register", Registration: &reg})
	before := leader.Raft.LastIndex()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := leader.Execute(ctx, blocked); err == nil {
		t.Fatal("old admission response accepted")
	}
	if leader.Raft.LastIndex() != before {
		t.Fatal("unadmitted change appended")
	}
}
