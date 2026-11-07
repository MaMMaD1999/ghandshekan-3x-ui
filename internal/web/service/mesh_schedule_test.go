package service

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestEnrollmentCapturesClientAndInboundResetSchedule(t *testing.T) {
	_, node := enrollmentAdminFixture(t)
	if err := node.DB.Model(&model.ClientRecord{}).Where("email = ?", "phone").Updates(map[string]any{"traffic_reset": "monthly", "traffic_reset_day": 31}).Error; err != nil {
		t.Fatal(err)
	}
	if err := node.DB.Model(&model.Inbound{}).Where("tag = ?", "one").Update("traffic_reset", "daily").Error; err != nil {
		t.Fatal(err)
	}
	if err := node.DB.Exec("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", "timeLocation", "Local").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := enrollmentResetSchedule(node.DB, []string{"phone"}); err == nil {
		t.Fatal("ambiguous per-node time zone accepted")
	}
	if err := node.DB.Exec("UPDATE settings SET value=? WHERE key=?", "Asia/Tehran", "timeLocation").Error; err != nil {
		t.Fatal(err)
	}
	s, err := enrollmentResetSchedule(node.DB, []string{"phone"})
	if err != nil || s == nil || s.Zone != "Asia/Tehran" || !s.Daily || !reflect.DeepEqual(s.MonthDays, []int{31}) || s.StartedAt <= 0 {
		t.Fatal("schedule was not preserved", s, err)
	}
}

func TestEnrolledInboundScheduleCannotSilentlyDiverge(t *testing.T) {
	db, inbound, _ := legacyGuardFixture(t)
	changed := *inbound
	changed.TrafficReset = "daily"
	if err := requireMeshInboundIdentity(db, inbound, &changed); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("changed local schedule outside policy", err)
	}
	unchanged := *inbound
	unchanged.Remark = "new display name"
	if err := requireMeshInboundIdentity(db, inbound, &unchanged); err != nil {
		t.Fatal("unrelated display change rejected", err)
	}
}
