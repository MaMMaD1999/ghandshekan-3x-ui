package quotaescrow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PolicyUpdate is an immutable authority command, safe to forward through a
// peer that has no administrative key. It has no wall-clock expiry: an isolated
// node must be able to catch up days later. Version/hash chaining prevents replay
// from resetting a subsequent cycle or changing membership implicitly.
type PolicyUpdate struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	PreviousHash string            `json:"previousHash"`
	Next         Policy            `json:"next"`
	Signature    []byte            `json:"signature"`
	Votes        map[string][]byte `json:"votes,omitempty"`
}

func PolicyHash(p Policy) string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(append([]byte("ghandshekan/shared-policy/v1\x00"), b...))
	return hex.EncodeToString(h[:])
}

func updatePayload(u PolicyUpdate) []byte {
	u.Signature = nil
	u.Votes = nil
	b, _ := json.Marshal(u)
	return append([]byte("ghandshekan/shared-update/v1\x00"), b...)
}

func SignPolicyUpdate(previous Policy, id, kind string, limit, expires int64, authority ed25519.PrivateKey) (PolicyUpdate, error) {
	return SignPolicyChange(previous, id, kind, ControlTarget{Limit: limit, ExpiresAt: expires, Disabled: previous.Disabled, Unlimited: previous.Unlimited}, authority)
}

func SignPolicyChange(previous Policy, id, kind string, target ControlTarget, authority ed25519.PrivateKey) (PolicyUpdate, error) {
	if previous.ControlEpoch != "" {
		return PolicyUpdate{}, errors.New("majority policy cannot be changed by the authority alone")
	}
	u := PolicyUpdate{ID: id, Kind: kind, PreviousHash: PolicyHash(previous), Next: clone(previous)}
	if previous.Version == math.MaxUint64 || len(authority) != ed25519.PrivateKeySize || !authority.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(previous.Authority)) {
		return u, errors.New("shared policy authority/version unavailable")
	}
	u.Next.Version++
	u.Next.Limit, u.Next.ExpiresAt = target.Limit, target.ExpiresAt
	u.Next.Disabled, u.Next.Unlimited = target.Disabled, target.Unlimited
	if kind == "reset" {
		if u.Next.ResetGeneration == math.MaxUint64 {
			return u, errors.New("generation exhausted")
		}
		u.Next.ResetGeneration++
		u.Next.AlreadyBilled = 0
	}
	u.Signature = ed25519.Sign(authority, updatePayload(u))
	return u, VerifyPolicyUpdate(previous, u)
}

// DraftPolicyChange has no authority to change a live ledger. It becomes
// admissible only after Raft commits it and a majority signs that exact value.
func DraftPolicyChange(previous Policy, id, kind string, target ControlTarget) (PolicyUpdate, error) {
	u := PolicyUpdate{ID: id, Kind: kind, PreviousHash: PolicyHash(previous), Next: clone(previous)}
	if previous.Version == math.MaxUint64 {
		return u, errors.New("version exhausted")
	}
	u.Next.Version++
	u.Next.Limit, u.Next.ExpiresAt = target.Limit, target.ExpiresAt
	u.Next.Disabled, u.Next.Unlimited = target.Disabled, target.Unlimited
	if kind == "reset" {
		if u.Next.ResetGeneration == math.MaxUint64 {
			return u, errors.New("generation exhausted")
		}
		u.Next.ResetGeneration++
		u.Next.AlreadyBilled = 0
	}
	return u, VerifyPolicyShape(previous, u)
}

func VerifyPolicyShape(previous Policy, u PolicyUpdate) error {
	if _, err := New(previous); err != nil {
		return err
	}
	if previous.Version == 0 || previous.Version == math.MaxUint64 || u.ID == "" || len(u.ID) > 128 || (u.Kind != "renew" && u.Kind != "reset") || u.PreviousHash != PolicyHash(previous) {
		return errors.New("invalid shared lifecycle transition")
	}
	if _, err := New(u.Next); err != nil {
		return err
	}
	expected := clone(previous)
	expected.Version++
	expected.Limit, expected.ExpiresAt = u.Next.Limit, u.Next.ExpiresAt
	expected.Disabled, expected.Unlimited = u.Next.Disabled, u.Next.Unlimited
	if u.Kind == "reset" {
		if expected.ResetGeneration == math.MaxUint64 {
			return errors.New("generation exhausted")
		}
		expected.ResetGeneration++
		expected.AlreadyBilled = 0
	}
	if !reflect.DeepEqual(expected, u.Next) {
		return errors.New("unauthorized policy, membership, or billing baseline change")
	}
	return nil
}

func PolicyUpdateVote(u PolicyUpdate, key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, updatePayload(u))
}
func VerifyPolicyVote(u PolicyUpdate, key, signature []byte) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, updatePayload(u), signature)
}

func VerifyPolicyUpdate(previous Policy, u PolicyUpdate) error {
	if err := VerifyPolicyShape(previous, u); err != nil {
		return err
	}
	if previous.ControlEpoch == "" {
		if len(u.Votes) != 0 || !ed25519.Verify(previous.Authority, updatePayload(u), u.Signature) {
			return errors.New("invalid policy authority")
		}
		return nil
	}
	if len(u.Signature) != 0 || len(u.Votes) <= len(previous.ControlKeys)/2 {
		return errors.New("policy requires a registered majority")
	}
	for owner, signature := range u.Votes {
		key := previous.ControlKeys[owner]
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, updatePayload(u), signature) {
			return errors.New("invalid policy quorum vote")
		}
	}
	return nil
}

// Different subsets of the same majority may certify one committed value.
// Certificate collection order must not turn a valid replay into a fork.
func SamePolicyUpdate(a, b PolicyUpdate) bool {
	a.Votes, b.Votes = nil, nil
	return reflect.DeepEqual(a, b)
}
func SamePolicyUpdates(a, b []PolicyUpdate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !SamePolicyUpdate(a[i], b[i]) {
			return false
		}
	}
	return true
}

func decodeUpdates(encoded string) ([]PolicyUpdate, error) {
	if encoded == "" {
		return nil, nil
	}
	var updates []PolicyUpdate
	err := json.Unmarshal([]byte(encoded), &updates)
	return updates, err
}

// validateSharedRecord checks the immutable certificate chain as well as any
// durable pending barrier. This also makes independent restore checkpoints able
// to distinguish an authorized reset from accidental counter/policy rollback.
func validateSharedRecord(r Record, p Policy) error {
	updates, err := decodeUpdates(r.UpdatesJSON)
	if err != nil {
		return err
	}
	pending, err := decodeUpdates(r.PendingUpdatesJSON)
	if err != nil {
		return err
	}
	if p.Version == 0 {
		if r.BasePolicyJSON != "" || len(updates) != 0 || len(pending) != 0 {
			return errors.New("legacy policy has shared lifecycle metadata")
		}
		return nil
	}
	var base Policy
	if json.Unmarshal([]byte(r.BasePolicyJSON), &base) != nil || base.Version != 1 || base.ResetGeneration != 1 {
		return errors.New("missing initial shared policy")
	}
	if _, err := New(base); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, u := range updates {
		if seen[u.ID] {
			return errors.New("reused lifecycle operation ID")
		}
		seen[u.ID] = true
		if err := VerifyPolicyUpdate(base, u); err != nil {
			return err
		}
		base = u.Next
	}
	if !reflect.DeepEqual(base, p) {
		return errors.New("policy differs from committed certificate chain")
	}
	for _, u := range pending {
		if seen[u.ID] {
			return errors.New("reused pending operation ID")
		}
		seen[u.ID] = true
		if err := VerifyPolicyUpdate(base, u); err != nil {
			return err
		}
		base = u.Next
	}
	if len(pending) > 0 && (r.PausedFor != pending[0].ID || r.PausedEpoch != p.Epoch) {
		return errors.New("missing shared lifecycle barrier")
	}
	return nil
}

func (s *Store) PolicyUpdates(subscription string) ([]PolicyUpdate, error) {
	var record Record
	if err := s.db.First(&record, "subscription = ?", subscription).Error; err != nil {
		return nil, err
	}
	if _, err := decodeRecord(record); err != nil {
		return nil, err
	}
	return decodeUpdates(record.UpdatesJSON)
}

// NeedsSharedUpdates validates replayed certificates without taking the core
// enforcement lock. Normal steady-state gossip must not drain or pause traffic.
func (s *Store) NeedsSharedUpdates(subscription string, incoming []PolicyUpdate) (bool, error) {
	var r Record
	if err := s.db.First(&r, "subscription = ?", subscription).Error; err != nil {
		return false, err
	}
	missing, err := missingUpdates(r, incoming)
	return len(missing) > 0, err
}

// missingUpdates accepts exact replays, but rejects even authority-signed forks
// of an already committed version. It does not replace pending work.
func missingUpdates(r Record, incoming []PolicyUpdate) ([]PolicyUpdate, error) {
	l, err := decodeRecord(r)
	if err != nil {
		return nil, err
	}
	history, err := decodeUpdates(r.UpdatesJSON)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, u := range history {
		seen[u.ID] = true
	}
	p := l.policy
	var missing []PolicyUpdate
	for i, u := range incoming {
		if i > 0 && u.Next.Version != incoming[i-1].Next.Version+1 {
			return nil, errors.New("unordered policy updates")
		}
		if u.Next.Version <= l.policy.Version {
			if u.Next.Version < 2 || u.Next.Version-2 >= uint64(len(history)) || !SamePolicyUpdate(history[u.Next.Version-2], u) {
				return nil, errors.New("conflicting replayed policy")
			}
			continue
		}
		if seen[u.ID] {
			return nil, errors.New("reused policy operation ID")
		}
		if err := VerifyPolicyUpdate(p, u); err != nil {
			return nil, err
		}
		seen[u.ID] = true
		missing = append(missing, clone(u))
		p = u.Next
	}
	return missing, nil
}

// BeginSharedUpdates durably fences only this local member. Other members do
// not have to acknowledge it. A restart or failed drain retains the barrier.
func (s *Store) BeginSharedUpdates(subscription string, incoming []PolicyUpdate) (bool, error) {
	needed := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var r Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, "subscription = ?", subscription).Error; err != nil {
			return err
		}
		missing, err := missingUpdates(r, incoming)
		if err != nil {
			return err
		}
		pending, err := decodeUpdates(r.PendingUpdatesJSON)
		if err != nil {
			return err
		}
		if len(missing) == 0 {
			return nil
		}
		if len(pending) > 0 {
			if len(missing) < len(pending) || !SamePolicyUpdates(missing[:len(pending)], pending) {
				return errors.New("different pending lifecycle command")
			}
		} else if r.PausedFor != "" || r.FrozenFor != "" {
			return ErrFrozen
		}
		if r.Revision == math.MaxUint64 {
			return errors.New("record revision exhausted")
		}
		body, _ := json.Marshal(missing)
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ?", subscription, r.Revision).Updates(map[string]any{"pending_updates_json": string(body), "paused_for": missing[0].ID, "paused_epoch": missing[0].Next.Epoch, "revision": r.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		needed = true
		return nil
	})
	return needed, err
}

// CommitSharedUpdates MUST run after the adapter drained sockets and settled
// every local lifetime meter. A reset advances the owner's signed baseline at
// local application time; disconnected old-generation usage is retained in
// lifetime counters, never billed against the new cycle. Renewals keep it all.
// Commit and the adapter's UI/card update must share a DB transaction.
func (s *Store) CommitSharedUpdates(subscription, owner string, key ed25519.PrivateKey) (Policy, string, error) {
	var applied Policy
	kind := "renew"
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var r Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, "subscription = ?", subscription).Error; err != nil {
			return err
		}
		l, err := decodeRecord(r)
		if err != nil {
			return err
		}
		pending, err := decodeUpdates(r.PendingUpdatesJSON)
		if err != nil {
			return err
		}
		if len(pending) == 0 || r.FrozenFor != "" {
			return errors.New("shared transition not prepared")
		}
		if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(l.policy.Keys[owner])) {
			return errors.New("wrong local lifecycle key")
		}
		next := pending[len(pending)-1].Next
		row := l.own(owner)
		if next.ResetGeneration != l.policy.ResetGeneration {
			kind = "reset"
			if row.Sequence == math.MaxUint64 {
				return errors.New("owner sequence exhausted")
			}
			row.Sequence++
			row.Generation, row.ResetAt = next.ResetGeneration, row.Used
			l.policy = next
			if err := l.Merge([]SignedRow{{Row: row, Signature: ed25519.Sign(key, payload(row))}}); err != nil {
				return err
			}
		} else {
			l.policy = next
		}
		history, _ := decodeUpdates(r.UpdatesJSON)
		history = append(history, pending...)
		p, _ := json.Marshal(next)
		rows, _ := json.Marshal(l.Snapshot())
		certs, _ := json.Marshal(history)
		if r.Revision == math.MaxUint64 {
			return errors.New("record revision exhausted")
		}
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ?", subscription, r.Revision).Updates(map[string]any{"policy_json": string(p), "rows_json": string(rows), "updates_json": string(certs), "pending_updates_json": "[]", "paused_for": "", "paused_epoch": "", "revision": r.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		applied = next
		return nil
	})
	return applied, kind, err
}

// ValidateSharedAdvance checks both policy authorization and continuity of a
// previously persisted barrier, without requiring offline members' freeze ACKs.
func validateSharedAdvance(previous, current Record, old, next *Ledger) error {
	if previous.BasePolicyJSON != current.BasePolicyJSON || next.policy.Version < old.policy.Version {
		return errors.New("shared policy rollback")
	}
	history, _ := decodeUpdates(current.UpdatesJSON)
	oldHistory, _ := decodeUpdates(previous.UpdatesJSON)
	if len(history) < len(oldHistory) || !SamePolicyUpdates(history[:len(oldHistory)], oldHistory) {
		return errors.New("shared policy history replaced")
	}
	pending, _ := decodeUpdates(previous.PendingUpdatesJSON)
	if len(pending) > 0 {
		newPending, _ := decodeUpdates(current.PendingUpdatesJSON)
		continuation := append(clone(history[len(oldHistory):]), newPending...)
		if len(continuation) < len(pending) || !SamePolicyUpdates(continuation[:len(pending)], pending) {
			return errors.New("pending shared update disappeared")
		}
	} else if previous.PausedFor != "" && (previous.PausedFor != current.PausedFor || previous.PausedEpoch != current.PausedEpoch) {
		return errors.New("non-shared barrier disappeared")
	}
	if previous.FrozenFor != current.FrozenFor || previous.FreezeJSON != current.FreezeJSON {
		return errors.New("strict freeze changed during shared lifecycle")
	}
	return dominates(next, old.Snapshot())
}
