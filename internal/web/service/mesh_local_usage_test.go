package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
	"testing"
)

func TestMeshLocalMeterExcludesExistingAndMirroredUsage(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	svc := InboundService{}
	if err := db.Create(&xray.ClientTraffic{Email: "mesh-local", Enable: true, Up: 1000, Down: 2000}).Error; err != nil {
		t.Fatal(err)
	}
	tick := func(up, down int64) error {
		return db.Transaction(func(tx *gorm.DB) error {
			return svc.addClientTraffic(tx, []*xray.ClientTraffic{{Email: "mesh-local", Up: up, Down: down}})
		})
	}
	if err := tick(40, 60); err != nil {
		t.Fatal(err)
	}
	var before model.LocalUsage
	if err := db.First(&before, "email = ?", "mesh-local").Error; err != nil {
		t.Fatal(err)
	}
	if before.Billed != 100 || before.Source == "" {
		t.Fatal(before)
	}
	if err := svc.AcceptGlobalTraffic("remote-master", []*xray.ClientTraffic{{Email: "mesh-local", Up: 100000, Down: 200000}}); err != nil {
		t.Fatal(err)
	}
	// Simulate the master importing node usage into its public aggregate.
	if err := db.Model(&xray.ClientTraffic{}).Where("email = ?", "mesh-local").Updates(map[string]any{"up": 500000, "down": 600000}).Error; err != nil {
		t.Fatal(err)
	}
	if err := tick(10, 20); err != nil {
		t.Fatal(err)
	}
	var after model.LocalUsage
	if err := db.First(&after, "email = ?", "mesh-local").Error; err != nil {
		t.Fatal(err)
	}
	if after.Billed != 130 || after.Source != before.Source {
		t.Fatal(after)
	}
	if _, err := (&ClientService{}).ResetAllTraffics(); err != nil {
		t.Fatal(err)
	}
	if err := tick(5, 5); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&after, "email = ?", "mesh-local").Error; err != nil {
		t.Fatal(err)
	}
	if after.Billed != 140 || after.Source != before.Source {
		t.Fatal("reset broke durable meter", after)
	}
}

func TestMeshLocalMeterAndOrdinaryTrafficCommitTogether(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	svc := InboundService{}
	if err := db.Create(&xray.ClientTraffic{Email: "rollback", Enable: true, Up: 10}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER fail_mesh_meter BEFORE INSERT ON mesh_local_usage BEGIN SELECT RAISE(ABORT, 'disk error'); END;").Error; err != nil {
		t.Fatal(err)
	}
	tick := func() error {
		return db.Transaction(func(tx *gorm.DB) error {
			return svc.addClientTraffic(tx, []*xray.ClientTraffic{{Email: "rollback", Up: 20}})
		})
	}
	if err := tick(); err == nil {
		t.Fatal("meter failure ignored")
	}
	var row xray.ClientTraffic
	if err := db.First(&row, "email = ?", "rollback").Error; err != nil {
		t.Fatal(err)
	}
	if row.Up != 10 {
		t.Fatal("ordinary usage committed without durable meter", row.Up)
	}
	if err := db.Exec("DROP TRIGGER fail_mesh_meter").Error; err != nil {
		t.Fatal(err)
	}
	if err := tick(); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&row, "email = ?", "rollback").Error; err != nil {
		t.Fatal(err)
	}
	if row.Up != 30 {
		t.Fatal("retried transaction double billed", row.Up)
	}
	var meter model.LocalUsage
	if err := db.First(&meter, "email = ?", "rollback").Error; err != nil {
		t.Fatal(err)
	}
	if meter.Billed != 20 {
		t.Fatal(meter.Billed)
	}
}
