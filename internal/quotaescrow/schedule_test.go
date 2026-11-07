package quotaescrow

import (
	"testing"
	"time"
)

func scheduleTime(t *testing.T, value string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestResetScheduleUsesCanonicalZoneAndOneBoundary(t *testing.T) {
	s := &ResetSchedule{Zone: "Asia/Tehran", StartedAt: 1, Daily: true, Weekly: true, MonthDays: []int{1}}
	now := scheduleTime(t, "2026-11-01T01:30:00Z")
	want := scheduleTime(t, "2026-10-31T20:30:00Z").Unix()
	for _, zone := range []string{"UTC", "America/New_York", "Asia/Shanghai", "Europe/Vienna"} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Due(now.In(loc), 0)
		if err != nil || got != want {
			t.Fatal(zone, got, want, err)
		}
		if repeated, err := s.Due(now.In(loc), got); err != nil || repeated != 0 {
			t.Fatal("repeated boundary", zone, repeated, err)
		}
	}
	// Starting a mesh mid-period preserves all already billed traffic.
	s.StartedAt = now.Unix()
	if got, err := s.Due(now, 0); err != nil || got != 0 {
		t.Fatal("enrollment reset consumption", got, err)
	}
}

func TestResetScheduleCalendarEdgesAndLongOutage(t *testing.T) {
	cases := []struct {
		name      string
		s         ResetSchedule
		now, want string
	}{
		{"short month", ResetSchedule{Zone: "UTC", StartedAt: 1, MonthDays: []int{30, 31}}, "2027-02-28T14:00:00Z", "2027-02-28T00:00:00Z"},
		{"before monthly day", ResetSchedule{Zone: "UTC", StartedAt: 1, MonthDays: []int{31}}, "2027-03-12T14:00:00Z", "2027-02-28T00:00:00Z"},
		{"leap day", ResetSchedule{Zone: "UTC", StartedAt: 1, MonthDays: []int{31}}, "2028-02-29T14:00:00Z", "2028-02-29T00:00:00Z"},
		{"weekly sunday", ResetSchedule{Zone: "UTC", StartedAt: 1, Weekly: true}, "2026-11-04T14:00:00Z", "2026-11-01T00:00:00Z"},
		{"hour before autumn fold", ResetSchedule{Zone: "America/New_York", StartedAt: 1, Hourly: true}, "2026-11-01T05:30:00Z", "2026-11-01T05:00:00Z"},
		{"hour after autumn fold", ResetSchedule{Zone: "America/New_York", StartedAt: 1, Hourly: true}, "2026-11-01T06:30:00Z", "2026-11-01T06:00:00Z"},
		{"spring jump", ResetSchedule{Zone: "America/New_York", StartedAt: 1, Hourly: true}, "2026-03-08T07:30:00Z", "2026-03-08T07:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now, want := scheduleTime(t, tc.now), scheduleTime(t, tc.want).Unix()
			got, err := tc.s.Due(now, 0)
			if err != nil || got != want {
				t.Fatal(got, want, err)
			}
			if replay, err := tc.s.Due(now, got); err != nil || replay != 0 {
				t.Fatal("outage replayed older periods", replay, err)
			}
		})
	}
}

func TestResetScheduleRejectsAmbiguousConfiguration(t *testing.T) {
	for _, s := range []*ResetSchedule{
		{Zone: "Local", StartedAt: 1, Daily: true}, {Zone: "UTC", Daily: true},
		{Zone: "UTC", StartedAt: 1}, {Zone: "UTC", StartedAt: 1, MonthDays: []int{32}},
		{Zone: "UTC", StartedAt: 1, MonthDays: []int{2, 1}}, {Zone: "UTC", StartedAt: 1, MonthDays: []int{1, 1}},
	} {
		if err := s.Validate(); err == nil {
			t.Fatal("invalid schedule accepted", s)
		}
	}
}
