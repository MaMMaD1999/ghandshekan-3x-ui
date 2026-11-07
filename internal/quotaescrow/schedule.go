package quotaescrow

import (
	"errors"
	"slices"
	"time"
	_ "time/tzdata"
)

// ResetSchedule travels with the authenticated policy. It never uses a node's
// local time zone or cron configuration. Multiple inherited schedules form a
// union: coincident boundaries still produce a single reset operation.
type ResetSchedule struct {
	Zone      string `json:"zone"`
	StartedAt int64  `json:"startedAt"`
	Hourly    bool   `json:"hourly,omitempty"`
	Daily     bool   `json:"daily,omitempty"`
	Weekly    bool   `json:"weekly,omitempty"`
	MonthDays []int  `json:"monthDays,omitempty"`
}

func (s *ResetSchedule) Validate() error {
	if s == nil {
		return nil
	}
	if s.Zone == "" || s.Zone == "Local" || len(s.Zone) > 128 || s.StartedAt <= 0 || (!s.Hourly && !s.Daily && !s.Weekly && len(s.MonthDays) == 0) || len(s.MonthDays) > 31 || !slices.IsSorted(s.MonthDays) {
		return errors.New("invalid canonical reset schedule")
	}
	if _, err := time.LoadLocation(s.Zone); err != nil {
		return errors.New("reset schedule requires a named time zone")
	}
	previous := 0
	for _, day := range s.MonthDays {
		if day < 1 || day > 31 || day == previous {
			return errors.New("invalid monthly reset days")
		}
		previous = day
	}
	return nil
}

// Due returns the newest elapsed boundary, not one reset per missed hour.
// Nodes catching up after a long outage therefore cannot repeatedly clear the
// newly resumed consumption. StartedAt prevents enrollment itself from resetting.
func (s *ResetSchedule) Due(now time.Time, through int64) (int64, error) {
	if s == nil {
		return 0, nil
	}
	if err := s.Validate(); err != nil {
		return 0, err
	}
	loc, _ := time.LoadLocation(s.Zone)
	t := now.In(loc)
	latest := int64(0)
	consider := func(candidate time.Time) {
		stamp := candidate.Unix()
		if stamp <= now.Unix() && stamp > max(s.StartedAt, through) && stamp > latest {
			latest = stamp
		}
	}
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	if s.Hourly {
		// Truncating a duration from midnight is wrong across DST. Keep the
		// current instant's offset when locating its local top-of-hour.
		consider(t.Add(-time.Duration(t.Minute())*time.Minute - time.Duration(t.Second())*time.Second - time.Duration(t.Nanosecond())))
	}
	if s.Daily {
		consider(midnight)
	}
	if s.Weekly {
		consider(midnight.AddDate(0, 0, -int(t.Weekday())))
	}
	for _, day := range s.MonthDays {
		for _, monthBack := range []int{0, -1} {
			first := time.Date(t.Year(), t.Month()+time.Month(monthBack), 1, 0, 0, 0, 0, loc)
			lastDay := first.AddDate(0, 1, -1).Day()
			consider(time.Date(first.Year(), first.Month(), min(day, lastDay), 0, 0, 0, 0, loc))
		}
	}
	return latest, nil
}
