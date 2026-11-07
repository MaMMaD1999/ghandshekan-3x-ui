// Package meshconsensus orders administrative policy changes. Usage metering
// and runtime cutoff deliberately do not depend on this quorum or its leader.
package meshconsensus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

const maxStateBytes = 64 << 20

type Registration struct {
	Policy    quotaescrow.Policy `json:"policy"`
	Signature []byte             `json:"signature"`
}

func registrationPayload(p quotaescrow.Policy) []byte {
	b, _ := json.Marshal(p)
	return append([]byte("ghandshekan/control-registration/v1\x00"), b...)
}

func SignRegistration(p quotaescrow.Policy, key ed25519.PrivateKey) (Registration, error) {
	r := Registration{Policy: p}
	if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(p.Authority)) {
		return r, errors.New("invalid registration authority")
	}
	r.Signature = ed25519.Sign(key, registrationPayload(p))
	return r, nil
}

// ExpectedHash provides compare-and-swap semantics for concurrent admin edits.
// The immutable request ID also survives retries through a different leader.
type Command struct {
	ID           string                    `json:"id"`
	Registration *Registration             `json:"registration,omitempty"`
	Subscription string                    `json:"subscription,omitempty"`
	Kind         string                    `json:"kind,omitempty"`
	ExpectedHash string                    `json:"expectedHash,omitempty"`
	Target       quotaescrow.ControlTarget `json:"target"`
	Patch        *PolicyPatch              `json:"patch,omitempty"`
}
type PolicyPatch struct {
	Limit     *int64 `json:"limit,omitempty"`
	ExpiresAt *int64 `json:"expiresAt,omitempty"`
	Disabled  *bool  `json:"disabled,omitempty"`
	Unlimited *bool  `json:"unlimited,omitempty"`
}
type Result struct {
	Error  string                    `json:"error,omitempty"`
	Update *quotaescrow.PolicyUpdate `json:"update,omitempty"`
}
type applied struct {
	Hash   string `json:"hash"`
	Result Result `json:"result"`
}
type subscription struct {
	Base    Registration               `json:"base"`
	Updates []quotaescrow.PolicyUpdate `json:"updates"`
}
type state struct {
	Epoch         string                  `json:"epoch"`
	Keys          map[string][]byte       `json:"keys"`
	Subscriptions map[string]subscription `json:"subscriptions"`
	Requests      map[string]applied      `json:"requests"`
}

type FSM struct {
	mu        sync.RWMutex
	authority ed25519.PublicKey
	data      state
}

func NewFSM(epoch string, keys map[string][]byte, authority ed25519.PublicKey) (*FSM, error) {
	if epoch == "" || len(epoch) > 128 || len(keys) < 3 || len(keys) > 256 || len(authority) != ed25519.PublicKeySize {
		return nil, errors.New("invalid control cluster")
	}
	seen := map[string]bool{}
	for id, key := range keys {
		if id == "" || len(id) > 128 || len(key) != ed25519.PublicKeySize || seen[string(key)] || reflect.DeepEqual(key, []byte(authority)) {
			return nil, errors.New("invalid control identity")
		}
		seen[string(key)] = true
	}
	return &FSM{authority: copyJSON(authority), data: state{Epoch: epoch, Keys: copyJSON(keys), Subscriptions: map[string]subscription{}, Requests: map[string]applied{}}}, nil
}

func copyJSON[T any](v T) T {
	b, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (f *FSM) validRegistration(r Registration) error {
	p := r.Policy
	if _, err := quotaescrow.New(p); err != nil {
		return err
	}
	if p.Version != 1 || p.ResetGeneration != 1 || p.ControlEpoch != f.data.Epoch || !reflect.DeepEqual(p.ControlKeys, f.data.Keys) || !reflect.DeepEqual(p.Authority, []byte(f.authority)) || !ed25519.Verify(f.authority, registrationPayload(p), r.Signature) {
		return errors.New("untrusted initial policy")
	}
	return nil
}

// Apply is invoked only by Raft after commitment. It never contacts a peer,
// drains a socket, or waits on the application database.
func (f *FSM) Apply(log *raft.Log) interface{} {
	var c Command
	if len(log.Data) > 1<<20 || json.Unmarshal(log.Data, &c) != nil || c.ID == "" || len(c.ID) > 128 {
		return Result{Error: "invalid control command"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h := digest(c)
	if old, ok := f.data.Requests[c.ID]; ok {
		if old.Hash != h {
			return Result{Error: "operation ID reused with different input"}
		}
		return copyJSON(old.Result)
	}
	out := f.apply(c)
	f.data.Requests[c.ID] = applied{Hash: h, Result: copyJSON(out)}
	return copyJSON(out)
}

func (f *FSM) apply(c Command) Result {
	if c.Registration != nil {
		if c.Subscription != "" || c.Kind != "" || c.ExpectedHash != "" || c.Patch != nil {
			return Result{Error: "mixed registration and mutation"}
		}
		if err := f.validRegistration(*c.Registration); err != nil {
			return Result{Error: err.Error()}
		}
		p := c.Registration.Policy
		if old, ok := f.data.Subscriptions[p.Subscription]; ok {
			if !reflect.DeepEqual(old.Base, *c.Registration) {
				return Result{Error: "subscription is already registered"}
			}
			return Result{}
		}
		f.data.Subscriptions[p.Subscription] = subscription{Base: copyJSON(*c.Registration)}
		return Result{}
	}
	sub, ok := f.data.Subscriptions[c.Subscription]
	if !ok {
		return Result{Error: "subscription is not registered"}
	}
	p := sub.Base.Policy
	if len(sub.Updates) > 0 {
		p = sub.Updates[len(sub.Updates)-1].Next
	}
	if (c.Patch == nil || c.ExpectedHash != "") && c.ExpectedHash != quotaescrow.PolicyHash(p) {
		return Result{Error: "policy changed; refresh before updating"}
	}
	target := c.Target
	if c.Patch != nil {
		if !reflect.DeepEqual(c.Target, quotaescrow.ControlTarget{}) {
			return Result{Error: "mixed target and patch"}
		}
		target = quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: p.Limit, ExpiresAt: p.ExpiresAt, Disabled: p.Disabled, Unlimited: p.Unlimited}
		if c.Patch.Limit != nil {
			target.Limit = *c.Patch.Limit
		}
		if c.Patch.ExpiresAt != nil {
			target.ExpiresAt = *c.Patch.ExpiresAt
		}
		if c.Patch.Disabled != nil {
			target.Disabled = *c.Patch.Disabled
		}
		if c.Patch.Unlimited != nil {
			target.Unlimited = *c.Patch.Unlimited
		}
	}
	if target.Mode != "shared" || !target.Eventual || len(target.Weights) != 0 {
		return Result{Error: "invalid shared target"}
	}
	u, err := quotaescrow.DraftPolicyChange(p, c.ID, c.Kind, target)
	if err != nil {
		return Result{Error: err.Error()}
	}
	sub.Updates = append(sub.Updates, u)
	f.data.Subscriptions[c.Subscription] = sub
	return Result{Update: &u}
}

func (f *FSM) Base(id string) (quotaescrow.Policy, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s, ok := f.data.Subscriptions[id]
	if !ok {
		return quotaescrow.Policy{}, errors.New("subscription is not registered")
	}
	return copyJSON(s.Base.Policy), nil
}

func (f *FSM) Policy(id string) (quotaescrow.Policy, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s, ok := f.data.Subscriptions[id]
	if !ok {
		return quotaescrow.Policy{}, errors.New("subscription is not registered")
	}
	if len(s.Updates) > 0 {
		return copyJSON(s.Updates[len(s.Updates)-1].Next), nil
	}
	return copyJSON(s.Base.Policy), nil
}
func (f *FSM) Updates(id string, after uint64) ([]quotaescrow.PolicyUpdate, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s, ok := f.data.Subscriptions[id]
	if !ok {
		return nil, errors.New("subscription is not registered")
	}
	var out []quotaescrow.PolicyUpdate
	for _, u := range s.Updates {
		if u.Next.Version > after {
			out = append(out, u)
		}
	}
	return copyJSON(out), nil
}

// Attest cannot sign caller-chosen content: the exact update must already be
// present in this member's committed FSM, including after snapshot recovery.
func (f *FSM) attest(u quotaescrow.PolicyUpdate, owner string, key ed25519.PrivateKey) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(f.data.Keys[owner])) {
		return nil, errors.New("invalid attestation identity")
	}
	s, ok := f.data.Subscriptions[u.Next.Subscription]
	if !ok || u.Next.Version < 2 || u.Next.Version-2 >= uint64(len(s.Updates)) || !quotaescrow.SamePolicyUpdate(s.Updates[u.Next.Version-2], u) {
		return nil, errors.New("policy was not committed here")
	}
	return quotaescrow.PolicyUpdateVote(u, key), nil
}

func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, err := json.Marshal(f.data)
	if len(b) > maxStateBytes {
		return nil, errors.New("control snapshot limit exceeded")
	}
	return snapshot(b), err
}

type snapshot []byte

func (s snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}
func (s snapshot) Release() {}
func (f *FSM) Restore(r io.ReadCloser) error {
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxStateBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxStateBytes {
		return errors.New("control snapshot too large")
	}
	var restored state
	if json.Unmarshal(b, &restored) != nil {
		return errors.New("invalid control snapshot")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if restored.Epoch != f.data.Epoch || !reflect.DeepEqual(restored.Keys, f.data.Keys) || restored.Subscriptions == nil || restored.Requests == nil {
		return errors.New("control snapshot membership mismatch")
	}
	for id, s := range restored.Subscriptions {
		if id != s.Base.Policy.Subscription {
			return errors.New("snapshot subscription mismatch")
		}
		if err := f.validRegistration(s.Base); err != nil {
			return err
		}
		p := s.Base.Policy
		seen := map[string]bool{}
		for _, u := range s.Updates {
			if seen[u.ID] || len(u.Votes) != 0 || len(u.Signature) != 0 {
				return errors.New("invalid snapshot update")
			}
			seen[u.ID] = true
			if err := quotaescrow.VerifyPolicyShape(p, u); err != nil {
				return err
			}
			p = u.Next
			request, ok := restored.Requests[u.ID]
			if !ok || request.Result.Update == nil || !quotaescrow.SamePolicyUpdate(*request.Result.Update, u) {
				return errors.New("snapshot lost operation identity")
			}
		}
	}
	f.data = restored
	return nil
}
