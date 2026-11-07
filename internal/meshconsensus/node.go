package meshconsensus

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

type Node struct {
	Raft  *raft.Raft
	FSM   *FSM
	Owner string
	Epoch string
	Key   ed25519.PrivateKey
	Keys  map[string][]byte
	// Calls target a fixed, mutually authenticated member registry.
	Call      func(context.Context, string, string, any, any) error
	store     *raftboltdb.BoltStore
	guard     *attestationGuard
	closeOnce sync.Once
}

type Options struct {
	Owner, Epoch, Directory string
	Keys                    map[string][]byte
	Key                     ed25519.PrivateKey
	Authority               ed25519.PublicKey
	Transport               raft.Transport
	Bootstrap               bool // Explicit initial provisioning only; never a repair action.
	Config                  *raft.Config
}

func Open(o Options) (*Node, error) {
	f, err := NewFSM(o.Epoch, o.Keys, o.Authority)
	if err != nil {
		return nil, err
	}
	if len(o.Key) != ed25519.PrivateKeySize || !o.Key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(o.Keys[o.Owner])) || o.Transport == nil || !filepath.IsAbs(o.Directory) {
		return nil, errors.New("invalid consensus host identity")
	}
	if err := os.MkdirAll(o.Directory, 0700); err != nil {
		return nil, err
	}
	st, err := os.Stat(o.Directory)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("consensus state directory must be private")
	}
	path := filepath.Join(o.Directory, "raft.db")
	// The sentinel lives outside the Raft directory so deleting/copying a DB
	// cannot silently bootstrap a second cluster under the same member identity.
	sentinel := o.Directory + ".initialized"
	guardPath := o.Directory + ".attestations.db"
	_, dbErr := os.Stat(path)
	_, markErr := os.Stat(sentinel)
	pin := o.Epoch + "\n" + digest(o.Keys) + "\n" + digest(o.Authority) + "\n" + o.Owner + "\n"
	if markErr == nil {
		b, e := os.ReadFile(sentinel)
		if e != nil {
			return nil, e
		}
		if string(b) != pin {
			return nil, errors.New("control identity or membership changed; explicit reconfiguration required")
		}
	}
	if errors.Is(dbErr, os.ErrNotExist) && markErr == nil {
		return nil, errors.New("consensus state was lost; explicit recovery required")
	}
	if _, e := os.Stat(guardPath); markErr == nil && e != nil {
		return nil, errors.New("independent attestation journal was lost; explicit recovery required")
	}
	if dbErr != nil && !errors.Is(dbErr, os.ErrNotExist) {
		return nil, dbErr
	}
	if markErr != nil && !errors.Is(markErr, os.ErrNotExist) {
		return nil, markErr
	}
	if errors.Is(dbErr, os.ErrNotExist) && !o.Bootstrap {
		return nil, errors.New("consensus has not been provisioned")
	}
	store, err := raftboltdb.NewBoltStore(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = store.Close()
		return nil, err
	}
	ok := false
	var guard *attestationGuard
	defer func() {
		if !ok {
			_ = store.Close()
			if guard != nil {
				guard.close()
			}
		}
	}()
	snaps, err := raft.NewFileSnapshotStore(o.Directory, 2, io.Discard)
	if err != nil {
		return nil, err
	}
	existing, err := raft.HasExistingState(store, store, snaps)
	if err != nil {
		return nil, err
	}
	if !existing && markErr == nil {
		return nil, errors.New("empty consensus store cannot replace initialized state")
	}
	const pinKey = "ghandshekan-control-membership-v1"
	storedPin, pinErr := store.Get([]byte(pinKey))
	if pinErr == nil && string(storedPin) != pin {
		return nil, errors.New("consensus store belongs to a different identity or membership")
	}
	if pinErr != nil {
		if !errors.Is(pinErr, raftboltdb.ErrKeyNotFound) {
			return nil, pinErr
		}
		if existing {
			return nil, errors.New("existing consensus state has no membership pin")
		}
		if err := store.Set([]byte(pinKey), []byte(pin)); err != nil {
			return nil, err
		}
	}
	guardStore, err := raftboltdb.NewBoltStore(guardPath)
	if err != nil {
		return nil, err
	}
	guard = &attestationGuard{store: guardStore}
	if err := os.Chmod(guardPath, 0600); err != nil {
		return nil, err
	}
	guardPin, e := guardStore.Get([]byte(pinKey))
	if e == nil && string(guardPin) != pin {
		return nil, errors.New("attestation journal belongs to a different control identity")
	}
	if e != nil {
		if !errors.Is(e, raftboltdb.ErrKeyNotFound) {
			return nil, e
		}
		if markErr == nil {
			return nil, errors.New("attestation journal lost its membership pin")
		}
		if e := guardStore.Set([]byte(pinKey), []byte(pin)); e != nil {
			return nil, e
		}
	}
	config := o.Config
	if config == nil {
		config = raft.DefaultConfig()
		config.HeartbeatTimeout = 8 * time.Second
		config.ElectionTimeout = 8 * time.Second
		config.LeaderLeaseTimeout = 8 * time.Second
		config.CommitTimeout = 100 * time.Millisecond
		config.SnapshotThreshold = 1024
	}
	config.LocalID = raft.ServerID(o.Owner)
	config.LogOutput = io.Discard
	if !existing {
		if !o.Bootstrap {
			return nil, errors.New("bootstrap must be explicitly authorized")
		}
		ids := make([]string, 0, len(o.Keys))
		for id := range o.Keys {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		membership := raft.Configuration{}
		for _, id := range ids {
			membership.Servers = append(membership.Servers, raft.Server{ID: raft.ServerID(id), Address: raft.ServerAddress(id), Suffrage: raft.Voter})
		}
		if err := raft.BootstrapCluster(config, store, store, snaps, o.Transport, membership); err != nil {
			return nil, err
		}
	}
	if errors.Is(markErr, os.ErrNotExist) {
		file, err := os.OpenFile(sentinel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, err = file.WriteString(pin)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if runtime.GOOS != "windows" {
			parent, err := os.Open(filepath.Dir(sentinel))
			if err != nil {
				return nil, err
			}
			err = parent.Sync()
			_ = parent.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	r, err := raft.NewRaft(config, f, store, store, snaps, o.Transport)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Node{Raft: r, FSM: f, Owner: o.Owner, Epoch: o.Epoch, Key: copyJSON(o.Key), Keys: copyJSON(o.Keys), store: store, guard: guard}, nil
}

func (n *Node) Close() {
	if n == nil {
		return
	}
	n.closeOnce.Do(func() {
		_ = n.Raft.Shutdown().Error()
		if n.store != nil {
			_ = n.store.Close()
		}
		n.guard.close()
	})
}

func (n *Node) Apply(ctx context.Context, c Command) (Result, error) {
	if n.Raft.State() != raft.Leader {
		return Result{}, raft.ErrNotLeader
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// A former leader retains its local Leader state briefly after isolation.
	// Confirm a live majority before appending a new administrative command;
	// otherwise a rejected minority renewal could linger in its log and become
	// committed after reconnection. A failure after admission remains ambiguous
	// and is retried with the same durable operation ID.
	verified := make(chan error, 1)
	fresh := n.Raft.VerifyLeader()
	go func() { verified <- fresh.Error() }()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case err := <-verified:
		if err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := n.admit(ctx, c); err != nil {
		return Result{}, err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return Result{}, err
	}
	if len(data) > 1<<20 {
		return Result{}, errors.New("command too large")
	}
	future := n.Raft.Apply(data, 2*time.Second)
	done := make(chan error, 1)
	go func() { done <- future.Error() }()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case err := <-done:
		if err != nil {
			return Result{}, err
		}
		out, ok := future.Response().(Result)
		if !ok {
			return Result{}, errors.New("invalid committed result")
		}
		if out.Error != "" {
			return out, errors.New(out.Error)
		}
		return out, nil
	}
}

// Execute never forces local leadership or shrinks membership. A minority
// cannot turn a successful HTTP response or a stale leader into a renewal.
func (n *Node) Execute(ctx context.Context, c Command) (Result, error) {
	if n.Raft.State() == raft.Leader {
		return n.Apply(ctx, c)
	}
	_, leader := n.Raft.LeaderWithID()
	if leader == "" || leader == raft.ServerID(n.Owner) || len(n.Keys[string(leader)]) == 0 || n.Call == nil {
		return Result{}, errors.New("control majority is unavailable")
	}
	var out Result
	if err := n.Call(ctx, string(leader), "propose", c, &out); err != nil {
		return out, err
	}
	if out.Error != "" {
		return out, errors.New(out.Error)
	}
	return out, nil
}

func (n *Node) Certify(ctx context.Context, previous quotaescrow.Policy, u quotaescrow.PolicyUpdate) (quotaescrow.PolicyUpdate, error) {
	if err := quotaescrow.VerifyPolicyShape(previous, u); err != nil {
		return u, err
	}
	if previous.ControlEpoch != n.Epoch || !equalKeys(previous.ControlKeys, n.Keys) {
		return u, errors.New("certificate membership mismatch")
	}
	u.Votes = map[string][]byte{}
	type answer struct {
		owner string
		vote  []byte
	}
	for ctx.Err() == nil {
		draft := copyJSON(u)
		draft.Votes = nil
		round, cancel := context.WithCancel(ctx)
		answers := make(chan answer, len(n.Keys))
		var wg sync.WaitGroup
		for owner := range n.Keys {
			if len(u.Votes[owner]) != 0 {
				continue
			}
			wg.Add(1)
			go func(owner string) {
				defer wg.Done()
				var vote []byte
				var err error
				if owner == n.Owner {
					vote, err = n.Attest(draft)
				} else if n.Call != nil {
					err = n.Call(round, owner, "attest", draft, &vote)
				} else {
					err = errors.New("no peer transport")
				}
				if err == nil {
					answers <- answer{owner, vote}
				}
			}(owner)
		}
		go func() { wg.Wait(); close(answers) }()
		for a := range answers {
			// Verify each signature before it contributes to the majority.
			if VerifyVote(u, n.Keys[a.owner], a.vote) {
				u.Votes[a.owner] = a.vote
			}
			if len(u.Votes) > len(n.Keys)/2 {
				cancel()
				for range answers {
				}
				return u, quotaescrow.VerifyPolicyUpdate(previous, u)
			}
		}
		cancel()
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return u, errors.New("committed policy is awaiting majority certificate; retry the same operation ID")
}

func VerifyVote(u quotaescrow.PolicyUpdate, key, signature []byte) bool {
	// Public verification shares the ledger's exact domain-separated payload.
	return quotaescrow.VerifyPolicyVote(u, key, signature)
}
func equalKeys(a, b map[string][]byte) bool { return digest(a) == digest(b) }

// Handler is invoked only inside the authenticated private RPC transport.
func (n *Node) Handle(ctx context.Context, kind string, body json.RawMessage) (any, error) {
	switch kind {
	case "propose":
		var c Command
		if json.Unmarshal(body, &c) != nil {
			return nil, errors.New("invalid proposal")
		}
		return n.Apply(ctx, c)
	case "submit":
		var c Command
		if json.Unmarshal(body, &c) != nil {
			return nil, errors.New("invalid proposal")
		}
		return n.Execute(ctx, c)
	case "attest":
		var u quotaescrow.PolicyUpdate
		if json.Unmarshal(body, &u) != nil {
			return nil, errors.New("invalid attestation")
		}
		return n.Attest(u)
	case "admit":
		var request admission
		if json.Unmarshal(body, &request) != nil || request.Nonce == "" || len(request.Nonce) > 128 || request.CommandHash == "" {
			return nil, errors.New("invalid control admission")
		}
		_, leader := n.Raft.LeaderWithID()
		if request.Leader != string(leader) || len(n.Keys[request.Leader]) == 0 || request.Term != n.Raft.Stats()["term"] {
			return nil, errors.New("control leader changed")
		}
		return request, nil
	default:
		return nil, errors.New("unknown control operation")
	}
}

type admission struct {
	Leader, Term, CommandHash, Nonce string
}

// Use a fresh, request-bound RPC as well as Raft's leadership check. A Raft
// verification can overlap an already in-flight heartbeat from before the
// request; that old response must not admit a newly isolated admin change.
func (n *Node) admit(ctx context.Context, c Command) error {
	if n.Call == nil {
		return errors.New("control majority is unavailable")
	}
	request := admission{Leader: n.Owner, Term: n.Raft.Stats()["term"], CommandHash: digest(c), Nonce: rand.Text()}
	round, cancel := context.WithCancel(ctx)
	defer cancel()
	answers := make(chan bool, len(n.Keys)-1)
	for owner := range n.Keys {
		if owner == n.Owner {
			continue
		}
		go func(owner string) {
			var response admission
			err := n.Call(round, owner, "admit", request, &response)
			answers <- err == nil && response == request
		}(owner)
	}
	count := 1
	for left := len(n.Keys) - 1; left > 0; left-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case accepted := <-answers:
			if accepted {
				count++
			}
			if count > len(n.Keys)/2 {
				return ctx.Err()
			}
		}
	}
	return errors.New("control majority did not admit this change")
}
