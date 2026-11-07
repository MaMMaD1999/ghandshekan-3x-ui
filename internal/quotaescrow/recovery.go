package quotaescrow

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type RecoveryResult struct {
	Operation string `json:"operation"`
	Complete  bool   `json:"complete"`
	Error     string `json:"error,omitempty"`
}

// RecoverPending advances only previously persisted administrator operations.
// It never creates a replacement ID, skips a missing proof, or invents a reset.
// The cursor prevents an unavailable first member from starving later jobs.
func (c *Coordinator) RecoverPending(ctx context.Context, after string, limit int, timeout time.Duration) (string, []RecoveryResult, error) {
	return recoverPending(ctx, c.DB, after, limit, timeout, func(child context.Context, id string) (bool, error) {
		_, complete, err := c.Resume(child, id)
		return complete, err
	})
}

func recoverPending(ctx context.Context, db *gorm.DB, after string, limit int, timeout time.Duration, resume func(context.Context, string) (bool, error)) (string, []RecoveryResult, error) {
	if db == nil || resume == nil || limit < 1 || limit > 32 || timeout <= 0 || timeout > 2*time.Minute {
		return after, nil, errors.New("invalid bounded recovery worker")
	}
	var ids []string
	query := db.WithContext(ctx).Model(&ControlJob{}).Where("complete = ? AND id > ?", false, after).Order("id").Limit(limit)
	if err := query.Pluck("id", &ids).Error; err != nil {
		return after, nil, err
	}
	if len(ids) == 0 {
		return "", nil, nil
	}
	results := make([]RecoveryResult, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return after, results, err
		}
		child, cancel := context.WithTimeout(ctx, timeout)
		done, err := resume(child, id)
		if err == nil && !done {
			err = errors.New("operation is still pending")
		}
		cancel()
		result := RecoveryResult{Operation: id, Complete: done && err == nil}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
		after = id
	}
	return after, results, nil
}
