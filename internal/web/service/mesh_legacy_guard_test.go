package service

import (
	"errors"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func legacyGuardFixture(t *testing.T) (*gorm.DB, *model.Inbound, model.Client) {
	t.Helper()
	setupBulkDB(t)
	db := database.GetDB()
	client := model.Client{Email: "mesh-user", ID: "aaaaaaaa-0000-0000-0000-000000000001", SubID: "mesh-sub", Enable: true, TotalGB: 1000, ExpiryTime: time.Now().Add(-time.Hour).UnixMilli(), Reset: 30}
	ib := mkInbound(t, 23145, model.VLESS, clientsSettings(t, []model.Client{client}))
	if err := (&ClientService{}).SyncInbound(nil, ib.Id, []model.Client{client}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{InboundId: ib.Id, Email: client.Email, Enable: true, Up: 600, Down: 400, Total: 1000, ExpiryTime: client.ExpiryTime, Reset: 30}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.MeshBinding{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.MeshBinding{Email: client.Email, Subscription: "sub", Owner: "local"}).Error; err != nil {
		t.Fatal(err)
	}
	return db, ib, client
}

func TestLegacyResetEndpointsCannotBypassMeshEpoch(t *testing.T) {
	for _, kind := range []string{"email", "inbound", "bulk", "all-clients", "all", "client-service", "direct-counter"} {
		t.Run(kind, func(t *testing.T) {
			db, ib, c := legacyGuardFixture(t)
			svc := &InboundService{}
			clients := &ClientService{}
			var err error
			switch kind {
			case "email":
				err = svc.ResetClientTrafficByEmail(c.Email)
			case "inbound":
				_, err = svc.ResetClientTraffic(ib.Id, c.Email)
			case "bulk":
				_, err = clients.BulkResetTraffic(svc, []string{c.Email})
			case "all-clients":
				err = clients.ResetAllClientTraffics(svc, ib.Id)
			case "all":
				_, err = clients.ResetAllTraffics()
			case "client-service":
				_, err = clients.ResetTrafficByEmail(svc, c.Email)
			case "direct-counter":
				err = svc.UpdateClientTrafficByEmail(c.Email, 0, 0)
			}
			if !errors.Is(err, errMeshLifecycleRequired) {
				t.Fatal("legacy reset accepted", err)
			}
			var after xray.ClientTraffic
			if err := db.First(&after, "email = ?", c.Email).Error; err != nil {
				t.Fatal(err)
			}
			if after.Up != 600 || after.Down != 400 || after.ExpiryTime != c.ExpiryTime {
				t.Fatal("failed reset changed usage", after)
			}
		})
	}
}

func TestLegacySettingsAndMembershipCannotBypassMeshControl(t *testing.T) {
	db, ib, c := legacyGuardFixture(t)
	changed := c
	changed.TotalGB = 9000
	copy := *ib
	copy.Settings = clientsSettings(t, []model.Client{changed})
	if err := db.Transaction(func(tx *gorm.DB) error { return commitInboundClientSettings(tx, &copy, ib.Settings) }); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("settings changed managed quota", err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return (&ClientService{}).SyncInbound(tx, ib.Id, []model.Client{changed}) }); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("record changed managed quota", err)
	}
	if err := (&ClientService{}).DetachInbound(db, ib.Id); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("deleted managed links", err)
	}
	if err := (&ClientService{}).SyncInbound(db, ib.Id, nil); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("pruned managed links", err)
	}
	other := mkInbound(t, 23146, model.VLESS, clientsSettings(t, nil))
	if err := (&ClientService{}).SyncInbound(db, other.Id, []model.Client{c}); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("attached without admission", err)
	}
	var stored model.ClientRecord
	if err := db.First(&stored, "email = ?", c.Email).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TotalGB != 1000 {
		t.Fatal("managed quota changed")
	}
	if _, err := (&ClientService{}).Delete(&InboundService{}, stored.Id, false); !errors.Is(err, errMeshLifecycleRequired) {
		t.Fatal("deleted managed subscription", err)
	}
}

func TestLegacyTimerLeavesManagedRenewalAndDisableToMesh(t *testing.T) {
	db, _, c := legacyGuardFixture(t)
	svc := &InboundService{}
	if _, n, err := svc.autoRenewClients(db, newTrafficMutationBatch()); err != nil || n != 0 {
		t.Fatal("legacy renewal ran", n, err)
	}
	if _, n, _, err := svc.disableInvalidClients(db, newTrafficMutationBatch()); err != nil || n != 0 {
		t.Fatal("legacy global disable ran", n, err)
	}
	var stored xray.ClientTraffic
	if err := db.First(&stored, "email = ?", c.Email).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.Enable || stored.ExpiryTime != c.ExpiryTime || stored.Up != 600 {
		t.Fatal("legacy timer changed managed lifecycle", stored)
	}
}
