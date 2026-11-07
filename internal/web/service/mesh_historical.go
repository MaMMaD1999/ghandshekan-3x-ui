package service

import (
	"errors"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"gorm.io/gorm"
)

// CaptureMeshHistorical reads the exact aggregate and child baselines in one
// transaction AFTER this member's durable admission barrier/drain. A pending
// legacy reset makes the cutover ambiguous and must be resolved first. Global
// display overlays are deliberately excluded: they include other nodes again.
func CaptureMeshHistorical(tx *gorm.DB, owner string, emails []string) (quotaescrow.LegacySnapshot, error) {
	out := quotaescrow.LegacySnapshot{Owner: owner, Aliases: map[string]quotaescrow.LegacyAliasSnapshot{}}
	if owner == "" || len(emails) == 0 {
		return out, errors.New("empty historical scope")
	}
	var pending int64
	if err := tx.Model(&model.NodePendingReset{}).Where("email IN ?", emails).Count(&pending).Error; err != nil {
		return out, err
	}
	if pending != 0 {
		return out, errors.New("legacy node resets must finish before enrollment")
	}
	var counters []xray.ClientTraffic
	if err := tx.Where("email IN ?", emails).Find(&counters).Error; err != nil {
		return out, err
	}
	if len(counters) != len(emails) {
		return out, errors.New("historical traffic row missing")
	}
	for _, counter := range counters {
		if counter.Up < 0 || counter.Down < 0 {
			return out, errors.New("negative historical usage")
		}
		out.Aliases[counter.Email] = quotaescrow.LegacyAliasSnapshot{Total: quotaescrow.LegacyCounter{Up: counter.Up, Down: counter.Down}}
	}
	var children []struct {
		Email  string
		NodeID int `gorm:"column:node_id"`
		Guid   string
		Dirty  bool `gorm:"column:config_dirty"`
	}
	if err := tx.Table("clients c").Select("DISTINCT c.email, n.id AS node_id, n.guid, n.config_dirty").Joins("JOIN client_inbounds ci ON ci.client_id = c.id").Joins("JOIN inbounds i ON i.id = ci.inbound_id").Joins("JOIN nodes n ON n.id = i.node_id").Where("c.email IN ?", emails).Scan(&children).Error; err != nil {
		return out, err
	}
	seen := map[string]int{}
	for _, child := range children {
		if child.Guid == "" || child.Guid == owner || child.Dirty {
			return out, errors.New("historical child identity/configuration is not stable")
		}
		if previous, ok := seen[child.Guid]; ok && previous != child.NodeID {
			return out, errors.New("historical child identity is duplicated")
		}
		seen[child.Guid] = child.NodeID
		var baseline model.NodeClientTraffic
		err := tx.Where("node_id = ? AND email = ?", child.NodeID, child.Email).Take(&baseline).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return out, err
		}
		// No imported snapshot yet means zero was counted, not that this
		// physical child may be omitted from the frozen accounting tree.
		value := out.Aliases[child.Email]
		value.Imports = append(value.Imports, quotaescrow.LegacyImport{Owner: child.Guid, Alias: child.Email, Counter: quotaescrow.LegacyCounter{Up: baseline.Up, Down: baseline.Down}})
		out.Aliases[child.Email] = value
	}
	for alias, value := range out.Aliases {
		slices.SortFunc(value.Imports, func(a, b quotaescrow.LegacyImport) int {
			if a.Owner < b.Owner {
				return -1
			}
			if a.Owner > b.Owner {
				return 1
			}
			return 0
		})
		out.Aliases[alias] = value
	}
	return out, nil
}
