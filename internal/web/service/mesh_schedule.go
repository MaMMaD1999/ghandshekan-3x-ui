package service

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func enrollmentResetSchedule(db *gorm.DB, emails []string) (*quotaescrow.ResetSchedule, error) {
	type row struct {
		Period string
		Day    int
	}
	var clients, inbounds []row
	if err := db.Table("clients").Select("traffic_reset AS period, traffic_reset_day AS day").Where("email IN ?", emails).Scan(&clients).Error; err != nil {
		return nil, err
	}
	if err := db.Table("inbounds i").Select("DISTINCT i.traffic_reset AS period, i.traffic_reset_day AS day").Joins("JOIN client_inbounds ci ON ci.inbound_id = i.id").Joins("JOIN clients c ON ci.client_id = c.id").Where("c.email IN ?", emails).Scan(&inbounds).Error; err != nil {
		return nil, err
	}
	s := &quotaescrow.ResetSchedule{StartedAt: time.Now().Unix()}
	for _, r := range append(clients, inbounds...) {
		switch r.Period {
		case "", "never":
		case "hourly":
			s.Hourly = true
		case "daily":
			s.Daily = true
		case "weekly":
			s.Weekly = true
		case "monthly":
			s.MonthDays = append(s.MonthDays, max(1, r.Day))
		default:
			return nil, errors.New("unsupported legacy traffic reset schedule")
		}
	}
	if !s.Hourly && !s.Daily && !s.Weekly && len(s.MonthDays) == 0 {
		return nil, nil
	}
	slices.Sort(s.MonthDays)
	s.MonthDays = slices.Compact(s.MonthDays)
	var setting struct{ Value string }
	if err := db.Table("settings").Select("value").Where("key = ?", "timeLocation").Scan(&setting).Error; err != nil {
		return nil, err
	}
	s.Zone = setting.Value
	if s.Zone == "" || s.Zone == "Local" {
		return nil, errors.New("select an explicit panel time zone before enrolling scheduled subscriptions")
	}
	return s, s.Validate()
}

// Only the current control leader schedules, and Execute still requires a live
// majority. A new leader computes the same request ID and committed boundary.
// Runtime quota/expiry enforcement remains independent of this scheduler.
func (q *MeshQuorum) scheduleDue(ctx context.Context, p quotaescrow.Policy, now time.Time) (bool, error) {
	if p.ResetSchedule == nil || p.Disabled || q.Node.Raft.State() != raft.Leader {
		return false, nil
	}
	at, err := p.ResetSchedule.Due(now, p.ScheduledThrough)
	if err != nil || at == 0 {
		return false, err
	}
	id, err := meshOperationID(p.Subscription, "scheduled-reset", "schedule/"+strconv.FormatInt(at, 10))
	if err != nil {
		return false, err
	}
	_, err = q.Node.Execute(ctx, meshconsensus.Command{ID: id, Subscription: p.Subscription, Kind: "scheduled-reset", Patch: &meshconsensus.PolicyPatch{ScheduledAt: at}})
	return err == nil, err
}

func (q *MeshQuorum) scheduleCycle(ctx context.Context, now time.Time) error {
	if q.Node.Raft.State() != raft.Leader {
		return nil
	}
	page := q.Node.FSM.SchedulePage(q.scheduleCursor, 16)
	var failures []error
	for _, p := range page {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.Join(failures...))
		}
		if _, err := q.scheduleDue(ctx, p, now); err != nil {
			failures = append(failures, err)
		}
		q.scheduleCursor = p.Subscription
	}
	if len(page) < 16 {
		q.scheduleCursor = ""
	}
	return errors.Join(failures...)
}
