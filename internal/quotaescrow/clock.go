package quotaescrow

import (
	"errors"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrClockRollback = errors.New("accounting clock precedes its durable high-water mark")

// ClockState is a durable time floor, not protection against restoring the whole
// database. Restore fencing must additionally validate the external checkpoint.
type ClockState struct {
	ID       string `gorm:"primaryKey"`
	LastUnix int64
}

func (ClockState) TableName() string { return "quota_escrow_clock" }

// InitializeClock is allowed only during explicit enrollment, before admission.
// Runtime readers never silently recreate a missing clock after a restore.
func InitializeClock(db *gorm.DB, now time.Time) error {
	if now.Unix() <= 0 {
		return ErrClockRollback
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&ClockState{ID: "local", LastUnix: now.Unix()}).Error
}

type ClockGuard struct {
	mu       sync.Mutex
	base     time.Time
	baseUnix int64
}

// Unix combines the process monotonic clock with a durable wall-clock floor.
// A running process cannot extend expiry by moving its wall clock backwards.
// After restart, a wall clock more than two seconds behind committed time fails
// closed until it catches up. Small NTP corrections use the committed floor.
func (c *ClockGuard) Unix(db *gorm.DB, now time.Time) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if db == nil || now.Unix() <= 0 {
		return 0, ErrClockRollback
	}
	var checked int64
	rebase := c.base.IsZero()
	err := db.Transaction(func(tx *gorm.DB) error {
		var state ClockState
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&state, "id = ?", "local").Error; err != nil {
			return err
		}
		if state.LastUnix <= 0 {
			return ErrClockRollback
		}
		candidate := now.Unix()
		if c.base.IsZero() {
			if candidate < state.LastUnix-2 {
				return ErrClockRollback
			}
		} else {
			elapsed := now.Sub(c.base)
			if elapsed < 0 {
				return ErrClockRollback
			}
			candidate = max(candidate, c.baseUnix+int64(elapsed/time.Second))
		}
		checked = max(candidate, state.LastUnix)
		if !c.base.IsZero() && checked > c.baseUnix+int64(now.Sub(c.base)/time.Second) {
			rebase = true
		}
		result := tx.Model(&ClockState{}).Where("id = ? AND last_unix = ?", "local", state.LastUnix).Update("last_unix", checked)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if rebase {
		c.base, c.baseUnix = now, checked
	}
	return checked, nil
}
