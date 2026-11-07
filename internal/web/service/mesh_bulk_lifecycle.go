package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// ResetManyWithMesh groups device aliases by subscription: a bulk request or
// overlapping scheduled inbounds can never issue one reset per device alias.
// Ordinary clients continue through the existing sidecar/node reset path.
func ResetManyWithMesh(ctx context.Context, emails []string, key string, scheduled bool) (handled bool, affected int, needRestart bool, err error) {
	db := database.GetDB()
	if !db.Migrator().HasTable(&model.MeshBinding{}) {
		return false, 0, false, nil
	}
	emails = trimmedUniqueEmails(emails)
	var bindings []model.MeshBinding
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []model.MeshBinding
		if err := db.Where("email IN ?", batch).Find(&rows).Error; err != nil {
			return false, 0, false, err
		}
		bindings = append(bindings, rows...)
	}
	if len(bindings) == 0 {
		return false, 0, false, nil
	}
	bound := map[string]bool{}
	groups := map[string][]model.MeshBinding{}
	for _, b := range bindings {
		bound[b.Email] = true
		groups[b.Subscription] = append(groups[b.Subscription], b)
	}
	var ordinary []string
	for _, email := range emails {
		if !bound[email] {
			ordinary = append(ordinary, email)
		}
	}
	a := activeMeshAdministrator.Load()
	var subscriptions []string
	for sub, group := range groups {
		var record quotaescrow.Record
		if err := db.First(&record, "subscription = ?", sub).Error; err != nil {
			return true, 0, false, err
		}
		var policy quotaescrow.Policy
		if json.Unmarshal([]byte(record.PolicyJSON), &policy) != nil || policy.Version == 0 {
			return true, 0, false, errMeshLifecycleRequired
		}
		if scheduled && policy.ControlEpoch == "" && policy.Manager != group[0].Owner {
			continue
		}
		if a == nil || (policy.ControlEpoch == "" && policy.Manager != a.Local.Owner) {
			return true, 0, false, errors.New("bulk lifecycle must run on the managing panel")
		}
		subscriptions = append(subscriptions, sub)
	}
	slices.Sort(subscriptions)
	if key == "" {
		key = rand.Text()
	}
	for _, sub := range subscriptions {
		if _, err := a.Queue(ctx, sub, "reset", key, nil, nil); err != nil {
			return true, affected, false, err
		}
		affected += len(groups[sub])
	}
	if len(ordinary) > 0 {
		count, err := (&ClientService{}).BulkResetTraffic(&InboundService{}, ordinary)
		return true, affected + count, count > 0, err
	}
	return true, affected, false, nil
}

func ResetAllWithMesh(ctx context.Context, key string) (bool, int, bool, error) {
	db := database.GetDB()
	if !db.Migrator().HasTable(&model.MeshBinding{}) {
		return false, 0, false, nil
	}
	var count int64
	if err := db.Model(&model.MeshBinding{}).Count(&count).Error; err != nil {
		return false, 0, false, err
	}
	if count == 0 {
		return false, 0, false, nil
	}
	var emails []string
	if err := db.Model(&xray.ClientTraffic{}).Pluck("email", &emails).Error; err != nil {
		return true, 0, false, err
	}
	return ResetManyWithMesh(ctx, emails, key, false)
}

func ResetInboundClientsWithMesh(ctx context.Context, id int, key string, scheduled bool) (bool, error) {
	var emails []string
	err := database.GetDB().Table("clients c").Joins("JOIN client_inbounds ci ON ci.client_id = c.id").Where("ci.inbound_id = ?", id).Pluck("c.email", &emails).Error
	if err != nil {
		return false, err
	}
	handled, _, _, err := ResetManyWithMesh(ctx, emails, key, scheduled)
	return handled, err
}
