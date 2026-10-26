package service

import (
	"context"
	"fmt"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

func ProNetCoreReady() bool {
	p := currentXrayProcess()
	if p == nil || !p.IsRunning() {
		return false
	}
	api := xray.XrayAPI{}
	if api.Init(p.GetAPIPort()) != nil {
		return false
	}
	defer api.Close()
	return api.HasProNetAccounting()
}

// A narrow compare-and-set never overwrites client membership or unrelated edits.
func (s *InboundService) SetTrafficCoefficient(id, userID int, rate float64, expected *float64) error {
	ib, err := s.GetInbound(id)
	if err != nil {
		return err
	}
	if ib.UserId != userID {
		return fmt.Errorf("inbound not found")
	}
	old := trafficRate(ib)
	if expected != nil && *expected != old {
		return fmt.Errorf("coefficient changed; refresh before saving")
	}
	ib.TrafficCoefficient = &rate
	if err = validateTrafficCoefficient(ib); err != nil {
		return err
	}
	if ib.NodeID != nil {
		rt, push, _, err := s.nodePushPlan(ib)
		if err != nil {
			return err
		}
		if !push {
			return fmt.Errorf("node unavailable for coefficient synchronization")
		}
		remote, ok := rt.(interface {
			SetTrafficCoefficient(context.Context, *model.Inbound, float64, *float64) error
		})
		if !ok {
			return fmt.Errorf("node does not support custom accounting")
		}
		if err = remote.SetTrafficCoefficient(context.Background(), ib, rate, expected); err != nil {
			return err
		}
	} else if !ProNetCoreReady() {
		return fmt.Errorf("custom accounting core is not running")
	}
	return submitTrafficWrite(func() error {
		return database.GetDB().Transaction(func(tx *gorm.DB) error {
			q := tx.Model(&model.Inbound{}).Where("id = ?", id)
			if expected != nil {
				q = q.Where("COALESCE(traffic_coefficient,1) = ?", *expected)
			}
			r := q.Update("traffic_coefficient", rate)
			if r.Error != nil {
				return r.Error
			}
			if r.RowsAffected != 1 {
				return fmt.Errorf("coefficient changed; refresh before saving")
			}
			return nil
		})
	})
}

// Subscription access has already resolved the authorized email list. Never
// return another client's traffic or any transport credentials in these cards.
func ProNetSubscriptionTraffic(emails []string) []model.InboundTrafficDetail {
	var rows []model.InboundTrafficDetail
	db := database.GetDB()
	if len(emails) == 0 || db == nil || !db.Migrator().HasTable(&model.InboundTrafficDetail{}) {
		return rows
	}
	if db.Where("email IN ?", emails).Order("origin_guid,inbound_tag,rate_parts").Find(&rows).Error != nil {
		return nil
	}
	nameTrafficRows(db, rows)
	applyTrafficReportBaselines(db, rows, emails)
	return rows
}

func (s *InboundService) ensureCoefficientRuntime(ib *model.Inbound) error {
	if trafficRate(ib) == 1 {
		return nil
	}
	if ib.NodeID == nil {
		if ProNetCoreReady() {
			return nil
		}
		return fmt.Errorf("custom accounting core is not running")
	}
	rt, _, _, err := s.nodePushPlan(ib)
	if err != nil {
		return err
	}
	probe, ok := rt.(interface{ HasProNetAccounting(context.Context) bool })
	if !ok || !probe.HasProNetAccounting(context.Background()) {
		return fmt.Errorf("node requires the ProNet panel and core; official nodes cannot apply inbound coefficients")
	}
	return nil
}
