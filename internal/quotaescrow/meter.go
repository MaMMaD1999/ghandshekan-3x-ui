package quotaescrow

import (
	"crypto/ed25519"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Meter binds one durable, local-only billed counter to a subscription owner.
// Source must include the stable client/device alias and counter generation.
// Never bind mirrored master totals or a reset-on-read Xray counter here.
type Meter struct {
	Subscription string `gorm:"primaryKey"`
	Owner        string `gorm:"primaryKey"`
	Source       string `gorm:"primaryKey"`
	Epoch        string
	Watermark    int64
}

func (Meter) TableName() string { return "quota_escrow_meters" }

// Activate atomically stores the policy and local counter watermarks. Existing
// consumption is supplied once in Policy.AlreadyBilled, not re-observed here.
// Production must keep runtime admission blocked until activation succeeds.
func (s *Store) Activate(p Policy, meters []Meter) error {
	if len(meters) == 0 {
		return errors.New("local meter baseline is required")
	}
	for _, m := range meters {
		if m.Subscription != p.Subscription || m.Epoch != p.Epoch || m.Source == "" || m.Watermark < 0 || len(p.Keys[m.Owner]) != ed25519.PublicKeySize {
			return errors.New("invalid local meter baseline")
		}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := NewStore(tx).Create(p); err != nil {
			return err
		}
		return tx.Create(&meters).Error
	})
}

// ObserveMeter commits the watermark and cumulative ledger usage together.
// Retried samples are no-ops; regressing counters are rejected, never treated
// as a fresh allowance or a negative delta. Counter generation changes need an
// explicit lifecycle transition by the panel adapter.
func (s *Store) ObserveMeter(subscription, owner, source string, key ed25519.PrivateKey, cumulative int64) error {
	if cumulative < 0 {
		return errors.New("negative local meter")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var meter Meter
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&meter, "subscription = ? AND owner = ? AND source = ?", subscription, owner, source).Error; err != nil {
			return err
		}
		if cumulative < meter.Watermark {
			return errors.New("local meter rollback: lifecycle transition required")
		}
		if cumulative == meter.Watermark {
			return nil
		}
		delta := cumulative - meter.Watermark
		if err := NewStore(tx).mutate(subscription, func(l *Ledger) error {
			if l.policy.Epoch != meter.Epoch {
				return ErrEpoch
			}
			next, err := add(l.own(owner).Used, delta)
			if err != nil {
				return err
			}
			row, err := l.Observe(owner, key, next)
			if err != nil {
				return err
			}
			return l.Merge([]SignedRow{row})
		}); err != nil {
			return err
		}
		result := tx.Model(&Meter{}).Where("subscription = ? AND owner = ? AND source = ? AND epoch = ? AND watermark = ?", subscription, owner, source, meter.Epoch, meter.Watermark).Update("watermark", cumulative)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
}

// Admission is local and does not depend on a successful master poll. An error
// must fail closed at the runtime adapter, not grant unmetered access.
func (s *Store) Admission(subscription, owner string, now int64) (int64, error) {
	l, err := s.Load(subscription)
	if err != nil {
		return 0, err
	}
	return l.Available(owner, now)
}
