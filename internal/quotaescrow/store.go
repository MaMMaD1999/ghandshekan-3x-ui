package quotaescrow

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Tables are migrated, but enrollment is not enabled until the runtime and
// membership adapters pass deployment acceptance tests.
type Record struct {
	Subscription string `gorm:"primaryKey"`
	Revision     uint64
	PolicyJSON   string
	RowsJSON     string
	FrozenFor    string `gorm:"not null;default:''"`
	FreezeJSON   string `gorm:"not null;default:''"`
	PausedFor    string `gorm:"not null;default:''"`
	PausedEpoch  string `gorm:"not null;default:''"`
}

func (Record) TableName() string { return "quota_escrow_states" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) *Store { return &Store{db: db} }

// Create never overwrites a previous epoch, even if its member is unreachable.
// Renewal/reset/membership changes require an explicit fenced transition.
func (s *Store) Create(p Policy) error {
	if _, err := New(p); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.db.Create(&Record{Subscription: p.Subscription, Revision: 1, PolicyJSON: string(b), RowsJSON: "[]"}).Error
}
func decodeRecord(r Record) (*Ledger, error) {
	var p Policy
	if err := json.Unmarshal([]byte(r.PolicyJSON), &p); err != nil {
		return nil, err
	}
	if p.Subscription != r.Subscription {
		return nil, errors.New("stored scope mismatch")
	}
	l, err := New(p)
	if err != nil {
		return nil, err
	}
	var rows []SignedRow
	if err = json.Unmarshal([]byte(r.RowsJSON), &rows); err != nil {
		return nil, err
	}
	if err = l.Merge(rows); err != nil {
		return nil, err
	}
	return l, nil
}
func (s *Store) Load(subscription string) (*Ledger, error) {
	var record Record
	if err := s.db.First(&record, "subscription = ?", subscription).Error; err != nil {
		return nil, err
	}
	return decodeRecord(record)
}

// mutate serializes updates with the DB, then uses a revision compare-and-swap
// as an additional fence (including dialects without row-level FOR UPDATE).
// No candidate leaves this transaction before successful durable commit.
func (s *Store) mutate(subscription string, fn func(*Ledger) error) error {
	return s.mutateMode(subscription, true, fn)
}

func (s *Store) mutateMode(subscription string, allowPaused bool, fn func(*Ledger) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var record Record
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&record, "subscription = ?", subscription).Error; err != nil {
			return err
		}
		if record.FrozenFor != "" || (!allowPaused && record.PausedFor != "") {
			return ErrFrozen
		}
		l, err := decodeRecord(record)
		if err != nil {
			return err
		}
		if err = fn(l); err != nil {
			return err
		}
		if record.Revision == ^uint64(0) {
			return errors.New("revision exhausted")
		}
		b, err := json.Marshal(l.Snapshot())
		if err != nil {
			return err
		}
		result := tx.Model(&Record{}).Where("subscription = ? AND revision = ?", subscription, record.Revision).
			Updates(map[string]any{"revision": record.Revision + 1, "rows_json": string(b)})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
}
func (s *Store) Merge(subscription string, rows []SignedRow) error {
	return s.mutate(subscription, func(l *Ledger) error { return l.Merge(rows) })
}
func (s *Store) Transfer(subscription, owner string, key ed25519.PrivateKey, bytes int64, to string, now int64) (SignedRow, error) {
	if to == "" {
		return SignedRow{}, errors.New("transfer recipient required")
	}
	var committed SignedRow
	err := s.mutateMode(subscription, false, func(l *Ledger) error {
		r, err := l.Propose(owner, key, bytes, to, now)
		if err != nil {
			return err
		}
		if err = l.Merge([]SignedRow{r}); err != nil {
			return err
		}
		committed = r
		return nil
	})
	if err != nil {
		return SignedRow{}, err
	}
	return committed, nil
}

// Observe uses a cumulative billed counter scoped to this accounting epoch.
// Replayed measurements are no-ops, never delta additions. The adapter must
// persist/restore its cumulative meter across core restarts; it must NOT pass a
// resettable core counter or apply an inbound coefficient a second time.
func (s *Store) Observe(subscription, owner string, key ed25519.PrivateKey, cumulative int64, now int64) error {
	if cumulative < 0 {
		return errors.New("negative meter")
	}
	return s.mutate(subscription, func(l *Ledger) error {
		old := l.own(owner).Used
		if cumulative < old {
			return errors.New("meter rollback: explicit epoch transition required")
		}
		if cumulative == old && l.own(owner).Spent == old {
			return nil
		}
		r, err := l.Observe(owner, key, cumulative)
		if err != nil {
			return err
		}
		return l.Merge([]SignedRow{r})
	})
}
