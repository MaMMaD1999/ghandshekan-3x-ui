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
	"math"
	"reflect"
	"slices"
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
	// Deltas are evaluated against the committed policy, never a follower's
	// potentially stale display. Repeating an operation ID cannot add twice.
	AddBytes    int64 `json:"addBytes,omitempty"`
	AddSeconds  int64 `json:"addSeconds,omitempty"`
	ScheduledAt int64 `json:"scheduledAt,omitempty"`
}
type Result struct {
	Error  string                    `json:"error,omitempty"`
	Update *quotaescrow.PolicyUpdate `json:"update,omitempty"`
}
type applied struct {
	Hash         string       `json:"hash"`
	Result       Result       `json:"result"`
	Subscription string       `json:"subscription,omitempty"`
	Value        *policyValue `json:"value,omitempty"`
}
type subscription struct {
	Base    Registration               `json:"base"`
	Updates []quotaescrow.PolicyUpdate `json:"updates"`
	TimerID string                     `json:"timerID,omitempty"`
	Timer   *applied                   `json:"timer,omitempty"`
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
	if err := validateTimerCommand(c); err != nil {
		return Result{Error: err.Error()}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h := digest(c)
	if old, ok := f.data.Requests[c.ID]; ok {
		if old.Hash != h {
			return Result{Error: "operation ID reused with different input"}
		}
		return old.result(f.data.Subscriptions)
	}
	if c.Kind == "scheduled-reset" {
		if sub, ok := f.data.Subscriptions[c.Subscription]; ok && sub.TimerID == c.ID && sub.Timer != nil {
			if sub.Timer.Hash != h {
				return Result{Error: "timer ID reused with different input"}
			}
			return sub.Timer.result(f.data.Subscriptions)
		}
	}
	out := f.apply(c)
	if c.Kind == "scheduled-reset" {
		if out.Update != nil {
			sub := f.data.Subscriptions[c.Subscription]
			saved := compactResult(c, out)
			sub.TimerID, sub.Timer = c.ID, &saved
			f.data.Subscriptions[c.Subscription] = sub
		}
	} else {
		f.data.Requests[c.ID] = compactResult(c, out)
	}
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
		target.ScheduledAt = c.Patch.ScheduledAt
		if c.Patch.AddBytes != 0 {
			if c.Patch.Limit != nil || c.Patch.Unlimited != nil {
				return Result{Error: "cannot combine absolute quota and relative quota"}
			}
			if !p.Unlimited {
				value, err := adjustPositive(p.Limit, c.Patch.AddBytes, math.MaxInt64)
				if err != nil {
					return Result{Error: err.Error()}
				}
				target.Limit = value
			}
		}
		if c.Patch.AddSeconds != 0 {
			if c.Patch.ExpiresAt != nil {
				return Result{Error: "cannot combine absolute expiry and relative expiry"}
			}
			if p.ExpiresAt != 0 {
				value, err := adjustPositive(p.ExpiresAt, c.Patch.AddSeconds, math.MaxInt64/1000)
				if err != nil {
					return Result{Error: err.Error()}
				}
				target.ExpiresAt = value
			}
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
	if len(sub.Updates) > 2 {
		// Keep the predecessor for exact shape validation and the latest value
		// for certification. Old manual retry results retain their small values.
		sub.Updates = copyJSON(sub.Updates[len(sub.Updates)-2:])
	}
	f.data.Subscriptions[c.Subscription] = sub
	return Result{Update: &u}
}

func adjustPositive(value, delta, ceiling int64) (int64, error) {
	// Avoid both wraparound and turning a reduction into the sentinel zero
	// (unlimited). Reject the whole command so a retry remains deterministic.
	if value < 0 || value > ceiling || delta > ceiling-value || delta <= -value {
		return 0, errors.New("relative adjustment exceeds the finite policy range")
	}
	return value + delta, nil
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

func (f *FSM) hasRequest(id string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.data.Requests[id]
	return ok
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

// SchedulePage includes subscriptions whose traffic is served by other nodes.
// Being elected control leader never requires a local client/accounting row.
func (f *FSM) SchedulePage(after string, limit int) []quotaescrow.Policy {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if limit < 1 || limit > 256 {
		return nil
	}
	latest := func(s subscription) quotaescrow.Policy {
		if len(s.Updates) > 0 {
			return s.Updates[len(s.Updates)-1].Next
		}
		return s.Base.Policy
	}
	var ids []string
	for id, sub := range f.data.Subscriptions {
		if id > after && latest(sub).ResetSchedule != nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	out := make([]quotaescrow.Policy, 0, min(limit, len(ids)))
	for _, id := range ids[:min(limit, len(ids))] {
		out = append(out, copyJSON(latest(f.data.Subscriptions[id])))
	}
	return out
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

// CommittedHead avoids copying an entire administrative history just to
// certify the newest majority decision for a returning member.
func (f *FSM) CommittedHead(id string) (quotaescrow.Policy, quotaescrow.PolicyUpdate, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s, ok := f.data.Subscriptions[id]
	if !ok || len(s.Updates) == 0 {
		return quotaescrow.Policy{}, quotaescrow.PolicyUpdate{}, errors.New("no committed policy update")
	}
	previous := s.Base.Policy
	if len(s.Updates) > 1 {
		previous = s.Updates[len(s.Updates)-2].Next
	}
	return copyJSON(previous), copyJSON(s.Updates[len(s.Updates)-1]), nil
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
	if !ok || !slices.ContainsFunc(s.Updates, func(committed quotaescrow.PolicyUpdate) bool { return quotaescrow.SamePolicyUpdate(committed, u) }) {
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
			if err := verifyCommittedAdvance(p, u); err != nil {
				return err
			}
			p = u.Next
			request, ok := restored.Requests[u.ID]
			if !ok && s.TimerID == u.ID && s.Timer != nil {
				request, ok = *s.Timer, true
			}
			// The previous timer's payload can precede the saved timer receipt;
			// its canonical boundary watermark prevents replay without a tombstone.
			if !ok && u.Kind == "scheduled-reset" && u.ID == ScheduledOperationID(id, u.Next.ScheduledThrough) && s.Timer != nil && s.Timer.Value != nil && u.Next.ScheduledThrough < s.Timer.Value.ScheduledThrough {
				continue
			}
			result := request.result(restored.Subscriptions)
			if !ok || result.Update == nil || !quotaescrow.SamePolicyUpdate(*result.Update, u) {
				return errors.New("snapshot lost operation identity")
			}
		}
		if len(s.Updates) > 2 {
			s.Updates = copyJSON(s.Updates[len(s.Updates)-2:])
			restored.Subscriptions[id] = s
		}
		if s.Timer != nil {
			out := s.Timer.result(restored.Subscriptions)
			if out.Update == nil || out.Update.Kind != "scheduled-reset" || s.TimerID != out.Update.ID || out.Update.ID != ScheduledOperationID(id, out.Update.Next.ScheduledThrough) || out.Update.Next.Subscription != id || out.Update.Next.Version > p.Version || out.Update.Next.ScheduledThrough > p.ScheduledThrough {
				return errors.New("invalid saved timer receipt")
			}
			if err := verifyCommittedAdvance(s.Base.Policy, *out.Update); err != nil {
				return err
			}
		}
	}
	for id, receipt := range restored.Requests {
		if _, err := hex.DecodeString(receipt.Hash); err != nil || len(receipt.Hash) != 64 {
			return errors.New("invalid saved operation fingerprint")
		}
		out := receipt.result(restored.Subscriptions)
		if receipt.Value != nil && (receipt.Result.Error != "" || receipt.Result.Update != nil || out.Error != "") {
			return errors.New("conflicting compact operation receipt")
		}
		if out.Update != nil {
			sub, exists := restored.Subscriptions[out.Update.Next.Subscription]
			if !exists || out.Update.ID != id || len(out.Update.Votes) != 0 || len(out.Update.Signature) != 0 {
				return errors.New("invalid saved operation result")
			}
			if err := verifyCommittedAdvance(sub.Base.Policy, *out.Update); err != nil {
				return err
			}
			if len(sub.Updates) == 0 || out.Update.Next.Version > sub.Updates[len(sub.Updates)-1].Next.Version {
				return errors.New("operation result exceeds committed version")
			}
			if receipt.Value == nil {
				compact := compactResult(Command{}, out)
				compact.Hash = receipt.Hash
				restored.Requests[id] = compact
			}
		}
	}
	f.data = restored
	return nil
}
