package quotaescrow

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrFrozen = errors.New("accounting epoch is fenced for transition")

// BeginTransition durably closes admission BEFORE the adapter drains active
// connections. Meter settlement and incoming cumulative usage remain possible
// until Freeze seals the final proof. A process restart therefore cannot reopen
// the old epoch in the interval between draining and signing its final usage.
// Authentication of the requested transition belongs to the control plane.
func (s *Store) BeginTransition(subscription, nextEpoch, transition string) error {
	if nextEpoch == "" || transition == "" {
		return errors.New("missing transition identity")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var r Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, "subscription = ?", subscription).Error; err != nil {
			return err
		}
		l, err := decodeRecord(r)
		if err != nil {
			return err
		}
		if nextEpoch == l.policy.Epoch {
			return ErrEpoch
		}
		if r.PausedFor != "" {
			if r.PausedFor == transition && r.PausedEpoch == nextEpoch {
				return nil
			}
			return ErrFrozen
		}
		if r.FrozenFor != "" {
			return ErrFrozen
		}
		if r.Revision == ^uint64(0) {
			return errors.New("revision exhausted")
		}
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ?", subscription, r.Revision).Updates(map[string]any{"paused_for": transition, "paused_epoch": nextEpoch, "revision": r.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
}

// FreezeProof is a member's final committed usage, signed only AFTER its
// runtime has stopped admission and settled outstanding traffic. A timeout
// is never a substitute for this proof, even if the master is reachable.
type FreezeProof struct {
	Subscription string      `json:"subscription"`
	Epoch        string      `json:"epoch"`
	NextEpoch    string      `json:"nextEpoch"`
	Transition   string      `json:"transition"`
	Owner        string      `json:"owner"`
	Rows         []SignedRow `json:"rows"`
	Signature    []byte      `json:"signature"`
}

func freezePayload(p FreezeProof) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("ghandshekan/quota-freeze/v1\x00"), b...)
}

// Freeze is the durable half of the runtime barrier. The panel adapter MUST
// stop admission, drain/settle its meter, and keep it stopped across restarts
// before calling this method. Calling Freeze alone does not stop Xray.
func (s *Store) Freeze(subscription, owner, nextEpoch, transition string, key ed25519.PrivateKey) (FreezeProof, error) {
	var proof FreezeProof
	if nextEpoch == "" || transition == "" {
		return proof, errors.New("missing transition identity")
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var r Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, "subscription = ?", subscription).Error; err != nil {
			return err
		}
		l, err := decodeRecord(r)
		if err != nil {
			return err
		}
		if r.Revision == ^uint64(0) {
			return errors.New("revision exhausted")
		}
		if l.policy.Epoch == nextEpoch {
			return ErrEpoch
		}
		if r.PausedFor != transition || r.PausedEpoch != nextEpoch {
			return errors.New("durable admission barrier required before freeze")
		}
		if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(l.policy.Keys[owner])) {
			return errors.New("wrong freeze signer")
		}
		if r.FrozenFor != "" {
			if r.FrozenFor != transition {
				return ErrFrozen
			}
			if err := json.Unmarshal([]byte(r.FreezeJSON), &proof); err != nil {
				return err
			}
			if proof.Owner != owner || proof.NextEpoch != nextEpoch {
				return ErrFrozen
			}
			return nil
		}
		proof = FreezeProof{Subscription: subscription, Epoch: l.policy.Epoch, NextEpoch: nextEpoch, Transition: transition, Owner: owner, Rows: l.Snapshot()}
		proof.Signature = ed25519.Sign(key, freezePayload(proof))
		b, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ? AND frozen_for = ?", subscription, r.Revision, "").Updates(map[string]any{"frozen_for": transition, "freeze_json": string(b), "revision": r.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return FreezeProof{}, err
	}
	return proof, nil
}

// CommitTransition requires a signed final proof from EVERY old owner. This
// prevents reset, renewal, or node replacement from resurrecting its old credit.
// Policy authentication and runtime barriers remain the panel adapter's job.
// kind=renew retains real prior consumption; kind=reset starts a new usage cycle.
func (s *Store) CommitTransition(next Policy, kind string, proofs []FreezeProof, meters []Meter) error {
	if kind != "renew" && kind != "reset" {
		return errors.New("invalid lifecycle operation")
	}
	if _, err := New(next); err != nil {
		return err
	}
	if len(meters) == 0 {
		return errors.New("new local meter baseline required")
	}
	for _, m := range meters {
		if m.Subscription != next.Subscription || m.Epoch != next.Epoch || m.Source == "" || m.Watermark < 0 || len(next.Keys[m.Owner]) != ed25519.PublicKeySize {
			return errors.New("invalid transition meter")
		}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var r Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&r, "subscription = ?", next.Subscription).Error; err != nil {
			return err
		}
		old, err := decodeRecord(r)
		if err != nil {
			return err
		}
		if r.FrozenFor == "" {
			if reflect.DeepEqual(old.policy, next) {
				return nil
			}
			return errors.New("local runtime epoch not fenced")
		}
		if r.Revision == ^uint64(0) {
			return errors.New("revision exhausted")
		}
		if old.policy.Epoch == next.Epoch {
			return ErrEpoch
		}
		var reused int64
		if err := tx.Model(&EpochArchive{}).Where("subscription = ? AND epoch = ?", next.Subscription, next.Epoch).Count(&reused).Error; err != nil {
			return err
		}
		if reused != 0 {
			return errors.New("accounting epoch cannot be reused")
		}
		if len(proofs) != len(old.policy.Keys) {
			return errors.New("every previous member must acknowledge fencing")
		}
		seen := map[string]bool{}
		rows := []SignedRow{}
		for _, p := range proofs {
			if p.Subscription != next.Subscription || p.Epoch != old.policy.Epoch || p.NextEpoch != next.Epoch || p.Transition != r.FrozenFor || seen[p.Owner] {
				return errors.New("invalid fence scope or duplicate owner")
			}
			key := old.policy.Keys[p.Owner]
			if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, freezePayload(p), p.Signature) {
				return errors.New("invalid fence signature")
			}
			seen[p.Owner] = true
			rows = append(rows, p.Rows...)
		}
		if err := old.Merge(rows); err != nil {
			return err
		}
		billed, err := old.Billed()
		if err != nil {
			return err
		}
		if (kind == "renew" && next.AlreadyBilled != billed) || (kind == "reset" && next.AlreadyBilled != 0) {
			return fmt.Errorf("new usage baseline does not match %s", kind)
		}
		// Retain the complete old epoch for audit/restore diagnosis; it is never
		// read as a new grant and cannot be reused by Create.
		archive, _ := json.Marshal(struct {
			Policy Policy
			Rows   []SignedRow
			Proofs []FreezeProof
		}{old.policy, old.Snapshot(), proofs})
		if err := tx.Create(&EpochArchive{Subscription: next.Subscription, Epoch: old.policy.Epoch, Transition: r.FrozenFor, JSON: string(archive)}).Error; err != nil {
			return err
		}
		policy, err := json.Marshal(next)
		if err != nil {
			return err
		}
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ? AND frozen_for = ?", next.Subscription, r.Revision, r.FrozenFor).Updates(map[string]any{"policy_json": string(policy), "rows_json": "[]", "frozen_for": "", "freeze_json": "", "paused_for": "", "paused_epoch": "", "revision": r.Revision + 1})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		if err := tx.Where("subscription = ?", next.Subscription).Delete(&Meter{}).Error; err != nil {
			return err
		}
		return tx.Create(&meters).Error
	})
}

type EpochArchive struct {
	Subscription string `gorm:"primaryKey"`
	Epoch        string `gorm:"primaryKey"`
	Transition   string
	JSON         string
}

func (EpochArchive) TableName() string { return "quota_escrow_epoch_archives" }
