package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

type meshReportScope struct {
	Epoch   string
	Pending bool
}

func meshReportRead(db *gorm.DB, read func(*gorm.DB) error) error {
	return db.Transaction(read, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
}

// All callers that mutate legacy snapshots run in the serialized traffic
// writer, as do the control barrier transactions. Therefore a request fetched
// before reset cannot be relabeled with or applied to the new accounting epoch.
func meshReportScopes(db *gorm.DB) (map[string]meshReportScope, error) {
	out := map[string]meshReportScope{}
	if db.Migrator().HasTable(&model.MeshBinding{}) {
		var bindings []model.MeshBinding
		if err := db.Find(&bindings).Error; err != nil {
			return nil, err
		}
		if len(bindings) > 0 {
			var records []quotaescrow.Record
			if err := db.Select("subscription", "policy_json").Find(&records).Error; err != nil {
				return nil, err
			}
			epochs := map[string]string{}
			for _, record := range records {
				var p quotaescrow.Policy
				if json.Unmarshal([]byte(record.PolicyJSON), &p) != nil || p.Subscription != record.Subscription || p.Epoch == "" {
					return nil, errors.New("invalid mesh reporting policy")
				}
				epochs[record.Subscription] = p.Epoch
				if p.Version > 0 {
					epochs[record.Subscription] += "/cycle/" + strconv.FormatUint(p.ResetGeneration, 10)
				}
			}
			for _, binding := range bindings {
				if epochs[binding.Subscription] == "" {
					return nil, errors.New("mesh reporting policy missing")
				}
				out[binding.Email] = meshReportScope{Epoch: epochs[binding.Subscription]}
			}
		}
	}
	pending, err := meshPendingAliases(db)
	if err != nil {
		return nil, err
	}
	for email := range pending {
		out[email] = meshReportScope{Pending: true}
	}
	return out, nil
}

func meshReportAccepted(scopes map[string]meshReportScope, email, epoch string) bool {
	scope, managed := scopes[email]
	return !managed || (!scope.Pending && epoch != "" && epoch == scope.Epoch)
}

func annotateMeshReports(db *gorm.DB, inbounds []*model.Inbound) error {
	scopes, err := meshReportScopes(db)
	if err != nil {
		return err
	}
	for _, inbound := range inbounds {
		for i := range inbound.ClientStats {
			inbound.ClientStats[i].MeshEpoch = scopes[inbound.ClientStats[i].Email].Epoch
		}
		for i := range inbound.DetailedTraffic {
			inbound.DetailedTraffic[i].MeshEpoch = scopes[inbound.DetailedTraffic[i].Email].Epoch
		}
	}
	return nil
}

// A legacy inbound snapshot can update ordinary clients, but it cannot change
// the membership or credentials of a managed alias. Lifecycle control owns
// those changes. Preserve exact existing entries, including absent ones.
func preserveMeshSettings(current, incoming string, scopes map[string]meshReportScope) (string, error) {
	if len(scopes) == 0 {
		return incoming, nil
	}
	var old, next map[string]json.RawMessage
	if json.Unmarshal([]byte(current), &old) != nil || json.Unmarshal([]byte(incoming), &next) != nil {
		return "", errors.New("invalid mesh client settings")
	}
	var previous, received []map[string]json.RawMessage
	if len(old["clients"]) > 0 && json.Unmarshal(old["clients"], &previous) != nil {
		return "", errors.New("invalid existing clients")
	}
	if len(next["clients"]) > 0 && json.Unmarshal(next["clients"], &received) != nil {
		return "", errors.New("invalid incoming clients")
	}
	kept := map[string]map[string]json.RawMessage{}
	for _, entry := range previous {
		var email string
		_ = json.Unmarshal(entry["email"], &email)
		if _, managed := scopes[email]; managed {
			kept[email] = entry
		}
	}
	merged := make([]map[string]json.RawMessage, 0, len(received)+len(kept))
	for _, entry := range received {
		var email string
		_ = json.Unmarshal(entry["email"], &email)
		if _, managed := scopes[email]; managed {
			continue
		}
		merged = append(merged, entry)
	}
	keys := make([]string, 0, len(kept))
	for email := range kept {
		keys = append(keys, email)
	}
	slices.Sort(keys)
	for _, email := range keys {
		merged = append(merged, kept[email])
	}
	body, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	next["clients"] = body
	body, err = json.Marshal(next)
	return string(body), err
}
