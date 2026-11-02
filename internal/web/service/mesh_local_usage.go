package service

import (
	"crypto/rand"
	"errors"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// recordMeshLocalUsage runs in the SAME transaction as the ordinary traffic
// write, after detailed traffic has been weighted and aliases canonicalized.
// A DB error rolls both counters back and the traffic job restores its Xray
// read baseline. Never call this on an imported node snapshot/global overlay.
func recordMeshLocalUsage(tx *gorm.DB, email string, up, down int64) error {
	if email == "" {
		return errors.New("missing local meter identity")
	}
	delta, err := addCounter(up, down)
	if err != nil {
		return err
	}
	if delta == 0 {
		return nil
	}
	row := model.LocalUsage{Email: email, Source: rand.Text(), Billed: delta}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.Assignments(map[string]any{"billed": gorm.Expr(database.ClampedAddExpr("mesh_local_usage.billed"), delta)}),
	}).Create(&row).Error
}
