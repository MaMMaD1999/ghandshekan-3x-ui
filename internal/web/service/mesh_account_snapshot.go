package service

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// These DTOs deliberately omit member keys, signatures and client credentials.
// The application adapter must bind a parent explicitly, merge each owner's
// cumulative row once, and never add this parent's total once per device alias.
type MeshAccountUsageRow struct {
	Owner        string `json:"owner"`
	Sequence     uint64 `json:"sequence"`
	LifetimeUsed int64  `json:"lifetimeUsed"`
	Generation   uint64 `json:"generation"`
	ResetAt      int64  `json:"resetAt"`
}

type MeshAccountSnapshot struct {
	Subscription    string                `json:"subscription"`
	ControlEpoch    string                `json:"controlEpoch"`
	Epoch           string                `json:"epoch"`
	PolicyVersion   uint64                `json:"policyVersion"`
	PolicyHash      string                `json:"policyHash"`
	ResetGeneration uint64                `json:"resetGeneration"`
	InitialBilled   int64                 `json:"initialBilled"`
	Billed          int64                 `json:"billed"`
	Limit           int64                 `json:"limit"`
	ExpiresAt       int64                 `json:"expiresAt"`
	Disabled        bool                  `json:"disabled"`
	Unlimited       bool                  `json:"unlimited"`
	Pending         bool                  `json:"pending"`
	Members         []string              `json:"members"`
	Rows            []MeshAccountUsageRow `json:"rows"`
}

// Read a bounded explicit parent list in one database snapshot. An unavailable
// or invalid record is an error, never an empty/zero counter that could rebase
// accounting. The app keeps the last verified snapshot when this read fails.
func ReadMeshAccounts(db *gorm.DB, subscriptions []string) ([]MeshAccountSnapshot, error) {
	if len(subscriptions) == 0 || len(subscriptions) > 100 {
		return nil, errors.New("between one and 100 explicit mesh subscriptions are required")
	}
	ids, seen := slices.Clone(subscriptions), map[string]bool{}
	for _, id := range ids {
		if id == "" || len(id) > 512 || strings.ContainsAny(id, "\x00\r\n") || seen[id] {
			return nil, errors.New("invalid or duplicate mesh subscription")
		}
		seen[id] = true
	}
	slices.Sort(ids)
	var result []MeshAccountSnapshot
	err := meshReportRead(db, func(tx *gorm.DB) error {
		store := quotaescrow.NewStore(tx)
		for _, id := range ids {
			ledger, err := store.Load(id)
			if err != nil {
				return errors.New("mesh accounting record is unavailable or invalid")
			}
			p := ledger.Policy()
			if p.ControlEpoch == "" || p.Mode != "shared" || p.Version == 0 || p.Aliases == nil {
				return errors.New("mesh parent accounting requires majority device membership")
			}
			used, err := ledger.Billed()
			if err != nil {
				return err
			}
			var record quotaescrow.Record
			if err := tx.First(&record, "subscription = ?", id).Error; err != nil {
				return err
			}
			var pending []quotaescrow.PolicyUpdate
			if json.Unmarshal([]byte(record.PendingUpdatesJSON), &pending) != nil {
				return errors.New("invalid pending accounting policy")
			}
			entry := MeshAccountSnapshot{Subscription: id, ControlEpoch: p.ControlEpoch, Epoch: p.Epoch,
				PolicyVersion: p.Version, PolicyHash: quotaescrow.PolicyHash(p), ResetGeneration: p.ResetGeneration,
				InitialBilled: p.AlreadyBilled, Billed: used, Limit: p.Limit, ExpiresAt: p.ExpiresAt,
				Disabled: p.Disabled, Unlimited: p.Unlimited,
				Pending: record.PausedFor != "" || record.FrozenFor != "" || len(pending) > 0,
				Rows:    []MeshAccountUsageRow{}}
			for owner := range p.Keys {
				entry.Members = append(entry.Members, owner)
			}
			slices.Sort(entry.Members)
			for _, signed := range ledger.Snapshot() {
				r := signed.Row
				entry.Rows = append(entry.Rows, MeshAccountUsageRow{Owner: r.Owner, Sequence: r.Sequence,
					LifetimeUsed: r.Used, Generation: r.Generation, ResetAt: r.ResetAt})
			}
			slices.SortFunc(entry.Rows, func(a, b MeshAccountUsageRow) int { return strings.Compare(a.Owner, b.Owner) })
			result = append(result, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
