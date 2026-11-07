package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"gorm.io/gorm"
)

// A subscription may have several device aliases. Bulk actions change its
// quota once, regardless of how many of those aliases the operator selected.
func meshBatchGroups(db *gorm.DB, emails []string) (map[string][]string, []string, error) {
	emails = trimmedUniqueEmails(emails)
	groups := map[string][]string{}
	if !db.Migrator().HasTable(&model.MeshBinding{}) {
		return groups, emails, nil
	}
	bound := map[string]bool{}
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []model.MeshBinding
		if err := db.Where("email IN ?", batch).Find(&rows).Error; err != nil {
			return nil, nil, err
		}
		for _, b := range rows {
			groups[b.Subscription] = append(groups[b.Subscription], b.Email)
			bound[b.Email] = true
		}
	}
	var ordinary []string
	for _, email := range emails {
		if !bound[email] {
			ordinary = append(ordinary, email)
		}
	}
	return groups, ordinary, nil
}

func ChangeManyWithMesh(ctx context.Context, emails []string, key string, patch *meshconsensus.PolicyPatch) (bool, int, []string, error) {
	groups, ordinary, err := meshBatchGroups(database.GetDB(), emails)
	if err != nil || len(groups) == 0 {
		return false, 0, ordinary, err
	}
	if strings.TrimSpace(key) == "" {
		return true, 0, ordinary, errors.New("mesh bulk changes require an Idempotency-Key")
	}
	a := activeMeshAdministrator.Load()
	if a == nil || a.Quorum == nil {
		return true, 0, ordinary, errors.New("majority control is unavailable for this bulk change")
	}
	return applyMeshBatch(ctx, groups, ordinary, key, patch, a.Quorum.QueuePatch)
}

func applyMeshBatch(ctx context.Context, groups map[string][]string, ordinary []string, key string, patch *meshconsensus.PolicyPatch, queue func(context.Context, string, string, string, *meshconsensus.PolicyPatch) (MeshOperationResult, error)) (bool, int, []string, error) {
	var subs []string
	for sub := range groups {
		subs = append(subs, sub)
	}
	slices.Sort(subs)
	count := 0
	for _, sub := range subs {
		if _, err := queue(ctx, sub, "renew", key, patch); err != nil {
			return true, count, ordinary, err
		}
		count += len(groups[sub])
	}
	return true, count, ordinary, nil
}
