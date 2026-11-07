// Package quotaescrow implements the accounting-independent spending-rights
// ledger. It is deliberately not advertised as a panel capability until durable
// storage, authenticated peer transport, and runtime enforcement are integrated.
package quotaescrow

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
)

var ErrInsufficient = errors.New("insufficient local spending rights")
var ErrEpoch = errors.New("different accounting epoch")
var ErrConflict = errors.New("conflicting owner sequence")

// Policy must be authenticated by the control plane before New is called.
// A new epoch is NOT an automatic right to reissue outstanding grants: old
// members must first be fenced. A disconnected member's grant cannot be reclaimed.
type Policy struct {
	// Mode is explicit and authenticated. Empty means reserved spending rights.
	// "shared" permits each member to use the remaining quota in its latest
	// signed view. During a partition the combined actual usage CAN exceed the
	// limit; reconciliation records those real bytes once, never as transfers.
	Mode         string `json:"mode,omitempty"`
	Subscription string `json:"subscription"`
	Epoch        string `json:"epoch"`
	Limit        int64  `json:"limit"`
	// AlreadyBilled is the committed subscription usage at mesh activation.
	// It is counted once globally, never copied into each member's Used row.
	AlreadyBilled int64             `json:"alreadyBilled,omitempty"`
	ExpiresAt     int64             `json:"expiresAt"`
	Grants        map[string]int64  `json:"grants"`
	Keys          map[string][]byte `json:"keys"`
	// Versioned shared policies keep one lifetime meter epoch. ResetGeneration
	// separates billing cycles without waiting for an unreachable member.
	Version         uint64 `json:"version,omitempty"`
	ResetGeneration uint64 `json:"resetGeneration,omitempty"`
	Authority       []byte `json:"authority,omitempty"`
	Manager         string `json:"manager,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
	Unlimited       bool   `json:"unlimited,omitempty"`
	// Control membership is pinned independently of traffic-serving members.
	// A relay/management voter need not carry this subscription's traffic.
	ControlEpoch string            `json:"controlEpoch,omitempty"`
	ControlKeys  map[string][]byte `json:"controlKeys,omitempty"`
}

// Row is a single-writer, monotonically increasing cumulative snapshot. Used
// contains real billed bytes, already weighted once. Spent is the part covered
// by rights. Their difference records real metering overrun; it is never lost.
// Transfers are reservations, never billable traffic. Sequence and counters
// survive process restarts.
type Row struct {
	Subscription string           `json:"subscription"`
	Epoch        string           `json:"epoch"`
	Owner        string           `json:"owner"`
	Sequence     uint64           `json:"sequence"`
	Spent        int64            `json:"spent"`
	Used         int64            `json:"used"`
	Sent         map[string]int64 `json:"sent"`
	Generation   uint64           `json:"generation,omitempty"`
	ResetAt      int64            `json:"resetAt,omitempty"`
}
type SignedRow struct {
	Row       Row    `json:"row"`
	Signature []byte `json:"signature"`
}
type Ledger struct {
	policy Policy
	rows   map[string]SignedRow
}

func (l *Ledger) Policy() Policy { return clone(l.policy) }

func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func payload(r Row) []byte {
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/quota-escrow/v1\x00"), b...)
}
func add(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, errors.New("invalid or overflowing byte counter")
	}
	return a + b, nil
}
func New(p Policy) (*Ledger, error) {
	if p.ControlEpoch != "" || len(p.ControlKeys) != 0 {
		if p.Version == 0 || p.ControlEpoch == "" || len(p.ControlEpoch) > 128 || len(p.ControlKeys) < 3 || len(p.ControlKeys) > 256 {
			return nil, errors.New("invalid control membership")
		}
		seen := map[string]bool{}
		for owner, key := range p.ControlKeys {
			if owner == "" || len(owner) > 128 || len(key) != ed25519.PublicKeySize || seen[string(key)] || reflect.DeepEqual(key, p.Authority) {
				return nil, errors.New("invalid control voter key")
			}
			seen[string(key)] = true
		}
		if len(p.ControlKeys[p.Manager]) != ed25519.PublicKeySize {
			return nil, errors.New("manager is not a control voter")
		}
	}
	if p.Version == 0 {
		if p.ResetGeneration != 0 || len(p.Authority) != 0 || p.Manager != "" || p.Disabled || p.Unlimited {
			return nil, errors.New("unversioned lifecycle metadata")
		}
	} else if p.Mode != "shared" || p.ResetGeneration == 0 || p.ResetGeneration > p.Version || len(p.Authority) != ed25519.PublicKeySize || len(p.Keys[p.Manager]) != ed25519.PublicKeySize {
		return nil, errors.New("invalid shared lifecycle authority/generation")
	}
	if p.Mode != "" && p.Mode != "shared" {
		return nil, errors.New("unknown quota availability mode")
	}
	if p.Subscription == "" || p.Epoch == "" || p.Limit < 0 || p.AlreadyBilled < 0 || p.ExpiresAt < 0 || len(p.Grants) == 0 || len(p.Keys) != len(p.Grants) {
		return nil, errors.New("invalid policy")
	}
	var total int64
	for owner, g := range p.Grants {
		if owner == "" || len(p.Keys[owner]) != ed25519.PublicKeySize {
			return nil, errors.New("invalid owner key")
		}
		var err error
		total, err = add(total, g)
		if err != nil {
			return nil, err
		}
	}
	remaining := p.Limit - min(p.Limit, p.AlreadyBilled)
	if p.Mode == "shared" && total != 0 {
		return nil, errors.New("shared mode does not allocate reserved rights")
	}
	if total > remaining {
		return nil, errors.New("grants exceed subscription limit")
	}
	return &Ledger{policy: clone(p), rows: map[string]SignedRow{}}, nil
}
func (l *Ledger) Snapshot() []SignedRow {
	out := make([]SignedRow, 0, len(l.rows))
	for _, r := range l.rows {
		out = append(out, clone(r))
	}
	return out
}
func (l *Ledger) own(owner string) Row {
	if s, ok := l.rows[owner]; ok {
		return clone(s.Row)
	}
	return Row{Subscription: l.policy.Subscription, Epoch: l.policy.Epoch, Owner: owner, Sent: map[string]int64{}, Generation: l.policy.ResetGeneration}
}
func (l *Ledger) balance(owner string) (int64, error) {
	credit, ok := l.policy.Grants[owner]
	if !ok {
		return 0, errors.New("unknown owner")
	}
	for _, s := range l.rows {
		var err error
		credit, err = add(credit, s.Row.Sent[owner])
		if err != nil {
			return 0, err
		}
	}
	r := l.own(owner)
	debit := r.Spent
	for _, v := range r.Sent {
		var err error
		debit, err = add(debit, v)
		if err != nil {
			return 0, err
		}
	}
	if debit > credit {
		return 0, ErrInsufficient
	}
	return credit - debit, nil
}
func (l *Ledger) Available(owner string, now int64) (int64, error) {
	if now < 0 {
		return 0, errors.New("invalid clock")
	}
	if l.policy.ExpiresAt > 0 && now >= l.policy.ExpiresAt {
		return 0, nil
	}
	if l.policy.Disabled {
		return 0, nil
	}
	if l.policy.Mode == "shared" {
		if _, exists := l.policy.Keys[owner]; !exists {
			return 0, errors.New("unknown owner")
		}
		if l.policy.Unlimited {
			return math.MaxInt64, nil
		}
		used, err := l.Billed()
		if err != nil {
			return 0, err
		}
		return l.policy.Limit - min(l.policy.Limit, used), nil
	}
	remaining, err := l.balance(owner)
	if err != nil {
		return 0, err
	}
	r := l.own(owner)
	// Actual traffic observed between polls must not disappear or be mistaken
	// for unspent rights when another peer subsequently transfers credit.
	debt := r.Used - r.Spent
	if debt >= remaining {
		return 0, nil
	}
	return remaining - debt, nil
}
func (l *Ledger) Billed() (int64, error) {
	total := l.policy.AlreadyBilled
	for _, s := range l.rows {
		var err error
		used := s.Row.Used
		if l.policy.Version > 0 {
			if s.Row.Generation != l.policy.ResetGeneration {
				continue
			}
			used -= s.Row.ResetAt
		}
		total, err = add(total, used)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

// Merge is atomic in memory. A storage adapter must commit the returned state
// durably before acknowledging it or allowing traffic/advertising a transfer.
// Whole snapshots carry incoming-credit dependencies; an incomplete dependency
// is rejected without mutating any counter and can be retried with a full view.
func (l *Ledger) Merge(updates []SignedRow) error {
	next := &Ledger{policy: l.policy, rows: clone(l.rows)}
	for _, signed := range updates {
		r := signed.Row
		if r.Epoch != l.policy.Epoch || r.Subscription != l.policy.Subscription {
			return ErrEpoch
		}
		key, ok := l.policy.Keys[r.Owner]
		if !ok || !ed25519.Verify(key, payload(r), signed.Signature) {
			return errors.New("invalid owner signature")
		}
		if r.Sequence == 0 || r.Spent < 0 || r.Used < r.Spent {
			return errors.New("invalid counters")
		}
		if r.ResetAt < 0 || r.ResetAt > r.Used || r.Generation > l.policy.ResetGeneration || (l.policy.Version == 0 && (r.Generation != 0 || r.ResetAt != 0)) || (l.policy.Version > 0 && r.Generation == 0) {
			return errors.New("invalid billing generation")
		}
		if l.policy.Mode == "shared" && r.Spent != 0 {
			return errors.New("shared usage cannot spend escrow rights")
		}
		for dest, v := range r.Sent {
			if l.policy.Mode == "shared" && v != 0 {
				return errors.New("shared usage cannot transfer escrow rights")
			}
			if _, ok := l.policy.Keys[dest]; !ok || dest == r.Owner || v < 0 {
				return errors.New("invalid transfer")
			}
		}
		old, exists := next.rows[r.Owner]
		if exists {
			if r.Sequence < old.Row.Sequence {
				continue
			}
			if r.Sequence == old.Row.Sequence {
				if !reflect.DeepEqual(r, old.Row) {
					return ErrConflict
				}
				continue
			}
			if r.Spent < old.Row.Spent || r.Used < old.Row.Used {
				return errors.New("spent counter rollback")
			}
			if r.Generation < old.Row.Generation || (r.Generation == old.Row.Generation && r.ResetAt != old.Row.ResetAt) || (r.Generation > old.Row.Generation && r.ResetAt < old.Row.Used) {
				return errors.New("billing baseline rollback or mutation")
			}
			for dest, v := range old.Row.Sent {
				if r.Sent[dest] < v {
					return errors.New("transfer counter rollback")
				}
			}
		}
		next.rows[r.Owner] = clone(signed)
	}
	for owner := range l.policy.Grants {
		if _, err := next.balance(owner); err != nil {
			return fmt.Errorf("owner %s: %w", owner, err)
		}
	}
	l.rows = next.rows
	return nil
}

// Propose returns a candidate snapshot WITHOUT committing it. The durable
// adapter must serialize proposals for one owner, persist, then apply/return it.
// With a recipient, amount transfers unused rights and does not affect Billed.
// Without a recipient it records actual, already-weighted consumption. The
// runtime adapter must use Observe for metering overrun rather than dropping
// it on ErrInsufficient. Polling-based enforcement cannot guarantee
// byte-exact cutoff; this package alone is not a traffic limiter.
func (l *Ledger) Propose(owner string, key ed25519.PrivateKey, amount int64, to string, now int64) (SignedRow, error) {
	if amount <= 0 {
		return SignedRow{}, errors.New("amount must be positive")
	}
	if len(key) != ed25519.PrivateKeySize || !reflect.DeepEqual([]byte(key.Public().(ed25519.PublicKey)), l.policy.Keys[owner]) {
		return SignedRow{}, errors.New("wrong owner key")
	}
	available, err := l.Available(owner, now)
	if err != nil {
		return SignedRow{}, err
	}
	if amount > available {
		return SignedRow{}, ErrInsufficient
	}
	if l.policy.Mode == "shared" {
		if to != "" {
			return SignedRow{}, errors.New("shared mode has no transferable reserved rights")
		}
		used, err := add(l.own(owner).Used, amount)
		if err != nil {
			return SignedRow{}, err
		}
		return l.Observe(owner, key, used)
	}
	r := l.own(owner)
	if r.Sequence == math.MaxUint64 {
		return SignedRow{}, errors.New("sequence exhausted")
	}
	r.Sequence++
	if to == "" {
		r.Spent, err = add(r.Spent, amount)
		if err == nil {
			r.Used, err = add(r.Used, amount)
		}
	} else {
		if _, ok := l.policy.Keys[to]; !ok || to == owner {
			return SignedRow{}, errors.New("invalid recipient")
		}
		r.Sent[to], err = add(r.Sent[to], amount)
	}
	if err != nil {
		return SignedRow{}, err
	}
	return SignedRow{Row: r, Signature: ed25519.Sign(key, payload(r))}, nil
}

// Observe records real cumulative usage even after expiry or a polling overrun.
// It never authorizes traffic. Available remains zero until debt is covered;
// late credit pays this debt before permitting another byte. Counter rollback
// needs a fenced epoch transition, not an implicit reset on reconnection.
func (l *Ledger) Observe(owner string, key ed25519.PrivateKey, cumulative int64) (SignedRow, error) {
	if len(key) != ed25519.PrivateKeySize || !reflect.DeepEqual([]byte(key.Public().(ed25519.PublicKey)), l.policy.Keys[owner]) {
		return SignedRow{}, errors.New("wrong owner key")
	}
	r := l.own(owner)
	if cumulative < r.Used || cumulative < 0 {
		return SignedRow{}, errors.New("meter rollback")
	}
	if r.Sequence == math.MaxUint64 {
		return SignedRow{}, errors.New("sequence exhausted")
	}
	credit, err := l.balance(owner)
	if err != nil {
		return SignedRow{}, err
	}
	r.Spent += min(credit, cumulative-r.Spent)
	r.Used = cumulative
	r.Sequence++
	return SignedRow{Row: r, Signature: ed25519.Sign(key, payload(r))}, nil
}
