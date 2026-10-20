package service

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const coefficientScale int64 = 1000000

func trafficRate(inbound *model.Inbound) float64 {
	if inbound.TrafficCoefficient == nil {
		return 1
	}
	return *inbound.TrafficCoefficient
}

func validateTrafficCoefficient(inbound *model.Inbound) error {
	r := trafficRate(inbound)
	if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 || r > 1000 || math.Abs(r*float64(coefficientScale)-math.Round(r*float64(coefficientScale))) > 0.00001 {
		return fmt.Errorf("traffic coefficient must be 0..1000, with at most six decimal places")
	}
	if r != 1 {
		switch inbound.Protocol {
		case model.VLESS, model.VMESS, model.Trojan, model.Shadowsocks:
		default:
			return fmt.Errorf("per-inbound coefficient currently requires VLESS, VMess, Trojan or Shadowsocks")
		}
	}
	return nil
}

// Fixed-point remainder prevents small packets or frequent polling losing bytes.
func weightedCounter(bytes, parts, remainder int64) (int64, int64, error) {
	if bytes < 0 || parts < 0 || remainder < 0 || remainder >= coefficientScale {
		return 0, 0, fmt.Errorf("invalid accounting counter")
	}
	n := new(big.Int).Mul(big.NewInt(bytes), big.NewInt(parts))
	n.Add(n, big.NewInt(remainder))
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(n, big.NewInt(coefficientScale), r)
	if !q.IsInt64() {
		return 0, 0, fmt.Errorf("weighted traffic overflow")
	}
	return q.Int64(), r.Int64(), nil
}

func addCounter(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, fmt.Errorf("traffic counter overflow")
	}
	return a + b, nil
}

// Detailed rows replace the corresponding portion of the ordinary email delta.
// They are NOT added to the original aggregate. Unattributed protocols remain 1x.
func weightDetailedTraffic(tx *gorm.DB, rows []*xray.ClientTraffic) ([]*xray.ClientTraffic, error) {
	hasDetails := false
	for _, row := range rows {
		if row != nil && row.InboundTag != "" {
			hasDetails = true
			break
		}
	}
	if !hasDetails {
		return rows, nil
	}
	details := map[string][]*xray.ClientTraffic{}
	totals := map[string]*xray.ClientTraffic{}
	var passthrough []*xray.ClientTraffic
	for _, r := range rows {
		if r == nil {
			continue
		}
		if r.TuicTrafficID > 0 || r.TuicUUID != "" || r.Email == "" {
			// Sidecar identity is resolved downstream; never merge it into an
			// Xray aggregate sharing an old or empty email.
			passthrough = append(passthrough, r)
		} else if r.InboundTag != "" {
			details[r.Email] = append(details[r.Email], r)
		} else {
			if totals[r.Email] == nil {
				copy := *r
				totals[r.Email] = &copy
			} else {
				var err error
				totals[r.Email].Up, err = addCounter(totals[r.Email].Up, r.Up)
				if err != nil {
					return nil, err
				}
				totals[r.Email].Down, err = addCounter(totals[r.Email].Down, r.Down)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	for email, parts := range details {
		total := totals[email]
		if total == nil {
			total = &xray.ClientTraffic{Email: email}
			totals[email] = total
		}
		rawUp, rawDown, billedUp, billedDown := int64(0), int64(0), int64(0), int64(0)
		for _, part := range parts {
			if part.Up == 0 && part.Down == 0 {
				continue
			}
			var inbound model.Inbound
			err := tx.Where("tag = ? AND node_id IS NULL", part.InboundTag).Take(&inbound).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				inbound = model.Inbound{Protocol: model.VLESS}
				err = nil
			} // Retain the final delta after deletion at 1x.
			if err != nil {
				return nil, err
			}
			if err = validateTrafficCoefficient(&inbound); err != nil {
				return nil, err
			}
			rate := int64(math.Round(trafficRate(&inbound) * float64(coefficientScale)))
			detail := model.InboundTrafficDetail{InboundTag: part.InboundTag, Email: email, RateParts: rate}
			err = tx.Where("origin_guid = ? AND inbound_tag = ? AND email = ? AND rate_parts = ?", "", part.InboundTag, email, rate).Take(&detail).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
			up, ru, err := weightedCounter(part.Up, rate, detail.RemainderUp)
			if err != nil {
				return nil, err
			}
			down, rd, err := weightedCounter(part.Down, rate, detail.RemainderDown)
			if err != nil {
				return nil, err
			}
			for _, pair := range []struct {
				target *int64
				value  int64
			}{
				{&detail.RawUp, part.Up}, {&detail.RawDown, part.Down}, {&detail.BilledUp, up}, {&detail.BilledDown, down},
				{&rawUp, part.Up}, {&rawDown, part.Down}, {&billedUp, up}, {&billedDown, down},
			} {
				*pair.target, err = addCounter(*pair.target, pair.value)
				if err != nil {
					return nil, err
				}
			}
			detail.RemainderUp, detail.RemainderDown = ru, rd
			detail.UpdatedAt = time.Now().UnixMilli()
			if inbound.Remark != "" {
				detail.InboundName = inbound.Remark
			}
			if err = recordTrafficHistory(tx, detail, part.Up, part.Down, up, down); err != nil {
				return nil, err
			}
			// Empty local origin and a free (zero) rate are valid key parts.
			// Save treats zero-valued primary keys as new rows; use an explicit
			// upsert so subsequent polls accumulate instead of failing uniqueness.
			if err = tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&detail).Error; err != nil {
				return nil, err
			}
		}
		// The aggregate and detailed counters are sampled separately by Xray.
		// Only the detailed series is authoritative once present; comparing their
		// instantaneous deltas would lose bytes during concurrent traffic.
		total.Up, total.Down = billedUp, billedDown

	}
	result := append(make([]*xray.ClientTraffic, 0, len(totals)+len(passthrough)), passthrough...)
	for _, r := range totals {
		result = append(result, r)
	}
	return result, nil
}

func attachDetailedTraffic(db *gorm.DB, inbounds []*model.Inbound) error {
	// Existing upstream test fixtures intentionally migrate only their own tables.
	if !db.Migrator().HasTable(&model.InboundTrafficDetail{}) {
		return nil
	}
	tags := make([]string, 0, len(inbounds))
	for _, ib := range inbounds {
		tags = append(tags, ib.Tag)
	}
	if len(tags) == 0 {
		return nil
	}
	var rows []model.InboundTrafficDetail
	if err := db.Where("inbound_tag IN ?", tags).Find(&rows).Error; err != nil {
		return err
	}
	for _, ib := range inbounds {
		ib.AccountingVersion = 1
		ib.DetailedTraffic = nil
		for _, row := range rows {
			origin := ib.OriginNodeGuid
			if ib.NodeID == nil {
				origin = ""
			}
			if row.InboundTag == ib.Tag && row.OriginGuid == origin {
				row.InboundName = ib.Remark
				ib.DetailedTraffic = append(ib.DetailedTraffic, row)
			}
		}
	}
	return nil
}

// Mirrored details are reporting data only: upstream's normal shared-client
// merge already receives billed totals. Never apply the coefficient here again.
func mirrorDetailedTraffic(tx *gorm.DB, remote, central *model.Inbound, origin string) error {
	for _, r := range remote.DetailedTraffic {
		if r.Email == "" || r.RawUp < 0 || r.RawDown < 0 || r.BilledUp < 0 || r.BilledDown < 0 {
			return fmt.Errorf("invalid remote detailed traffic")
		}
		r.OriginGuid = origin
		r.InboundTag = central.Tag
		r.InboundName = central.Remark
		r.RemainderUp = 0
		r.RemainderDown = 0
		var old model.InboundTrafficDetail
		err := tx.Where("origin_guid = ? AND inbound_tag = ? AND email = ? AND rate_parts = ?", origin, central.Tag, r.Email, r.RateParts).Take(&old).Error
		if err == nil && old.UpdatedAt >= r.UpdatedAt {
			continue
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		// First snapshot is a baseline, not traffic that occurred just now.
		if err == nil && r.RawUp >= old.RawUp && r.RawDown >= old.RawDown && r.BilledUp >= old.BilledUp && r.BilledDown >= old.BilledDown {
			if e := recordTrafficHistory(tx, r, r.RawUp-old.RawUp, r.RawDown-old.RawDown, r.BilledUp-old.BilledUp, r.BilledDown-old.BilledDown); e != nil {
				return e
			}
		}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&r).Error; err != nil {
			return err
		}
	}
	return nil
}
