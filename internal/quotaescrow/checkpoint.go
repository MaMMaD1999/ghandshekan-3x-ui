package quotaescrow

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
)

// ValidateCheckpointAdvance compares a live durable record with an independently
// saved floor. A higher revision alone is insufficient: all signed usage and
// transfer counters must dominate the prior snapshot. Epoch changes need the
// old epoch's complete, signed freeze archive.
func ValidateCheckpointAdvance(previous, current Record, archive *EpochArchive) error {
	old, err := decodeRecord(previous)
	if err != nil {
		return err
	}
	next, err := decodeRecord(current)
	if err != nil {
		return err
	}
	if previous.Revision == 0 || previous.Subscription != current.Subscription || current.Revision < previous.Revision {
		return errors.New("accounting checkpoint revision rollback")
	}
	if previous.Revision == current.Revision && !reflect.DeepEqual(previous, current) {
		return errors.New("conflicting checkpoint revision")
	}
	if old.policy.Epoch == next.policy.Epoch {
		if !reflect.DeepEqual(old.policy, next.policy) {
			return errors.New("policy changed without epoch transition")
		}
		if previous.PausedFor != "" && (previous.PausedFor != current.PausedFor || previous.PausedEpoch != current.PausedEpoch) {
			return errors.New("durable admission pause disappeared")
		}
		if previous.FrozenFor != "" && (previous.FrozenFor != current.FrozenFor || previous.FreezeJSON != current.FreezeJSON) {
			return errors.New("durable freeze disappeared")
		}
		return dominates(next, old.Snapshot())
	}
	if archive == nil || archive.Subscription != previous.Subscription || archive.Epoch != old.policy.Epoch || current.Revision <= previous.Revision {
		return errors.New("checkpoint epoch changed without archive")
	}
	var saved struct {
		Policy Policy
		Rows   []SignedRow
		Proofs []FreezeProof
	}
	if err := json.Unmarshal([]byte(archive.JSON), &saved); err != nil {
		return err
	}
	if !reflect.DeepEqual(saved.Policy, old.policy) || len(saved.Proofs) != len(old.policy.Keys) {
		return errors.New("checkpoint archive membership mismatch")
	}
	final, err := New(saved.Policy)
	if err != nil {
		return err
	}
	if err := final.Merge(saved.Rows); err != nil {
		return err
	}
	if err := dominates(final, old.Snapshot()); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, proof := range saved.Proofs {
		if proof.Subscription != old.policy.Subscription || proof.Epoch != old.policy.Epoch || proof.NextEpoch != next.policy.Epoch || proof.Transition != archive.Transition || seen[proof.Owner] {
			return errors.New("invalid checkpoint transition proof")
		}
		key := old.policy.Keys[proof.Owner]
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, freezePayload(proof), proof.Signature) {
			return errors.New("invalid checkpoint freeze signature")
		}
		if err := dominates(final, proof.Rows); err != nil {
			return err
		}
		seen[proof.Owner] = true
	}
	return nil
}

func dominates(current *Ledger, previous []SignedRow) error {
	before := current.rows
	copy := &Ledger{policy: clone(current.policy), rows: clone(current.rows)}
	if err := copy.Merge(previous); err != nil {
		return err
	}
	if !reflect.DeepEqual(before, copy.rows) {
		return errors.New("accounting counters precede external checkpoint")
	}
	return nil
}
