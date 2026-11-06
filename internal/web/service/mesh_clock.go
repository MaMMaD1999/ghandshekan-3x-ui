package service

import (
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

var meshLocalClock struct {
	sync.Mutex
	db    *gorm.DB
	guard quotaescrow.ClockGuard
}

func checkedMeshUnix(db *gorm.DB) (int64, error) {
	meshLocalClock.Lock()
	defer meshLocalClock.Unlock()
	if meshLocalClock.db != db {
		meshLocalClock.db = db
		meshLocalClock.guard = quotaescrow.ClockGuard{}
	}
	return meshLocalClock.guard.Unix(db, time.Now())
}

// Legacy installations do not need a mesh clock and incur no clock writes.
// Enrolled clients must have the floor initialized by authenticated enrollment.
func MeshBlockedEmailsNow(db *gorm.DB) (map[string]bool, error) {
	var bindings []model.MeshBinding
	if err := db.Find(&bindings).Error; err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return map[string]bool{}, nil
	}
	now, err := checkedMeshUnix(db)
	if err != nil {
		blocked := map[string]bool{}
		for _, binding := range bindings {
			blocked[binding.Email] = true
		}
		// Fence only enrolled aliases; a clock fault must not change legacy users.
		return blocked, nil
	}
	return MeshBlockedEmails(db, now)
}
