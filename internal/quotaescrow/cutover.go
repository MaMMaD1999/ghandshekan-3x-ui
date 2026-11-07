package quotaescrow

import "errors"

// LegacyCounter is an already-billed counter, never a raw transport counter.
// Imported baselines are the exact child snapshots included in that parent's
// Total. Subtracting those snapshots and adding the drained children brings the
// old authoritative total current without counting those children twice.
type LegacyCounter struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type LegacyImport struct {
	Owner   string        `json:"owner"`
	Alias   string        `json:"alias"`
	Counter LegacyCounter `json:"counter"`
}

type LegacyAliasSnapshot struct {
	Total   LegacyCounter  `json:"total"`
	Imports []LegacyImport `json:"imports,omitempty"`
}

type LegacySnapshot struct {
	Owner   string                         `json:"owner"`
	Aliases map[string]LegacyAliasSnapshot `json:"aliases"`
}

type LegacyRoot struct {
	Owner string `json:"owner"`
	Alias string `json:"alias"`
}

// PreparedHistoricalUsage uses only signed prepared snapshots. Callers verify
// receipt signatures against the independently provisioned member keys first.
func PreparedHistoricalUsage(plan ControlPlan, receipts []ControlReceipt) (int64, error) {
	if plan.Kind != "enroll" || len(plan.AccountingRoots) == 0 || len(receipts) != len(plan.Claims) {
		return 0, errors.New("complete frozen enrollment tree required")
	}
	snapshots := make([]LegacySnapshot, 0, len(receipts))
	seen := map[string]bool{}
	for _, receipt := range receipts {
		if receipt.PlanHash != ControlPlanHash(plan) || seen[receipt.Owner] || receipt.Historical == nil || receipt.Historical.Owner != receipt.Owner || len(receipt.Historical.Aliases) != len(plan.Claims[receipt.Owner]) || len(plan.Claims[receipt.Owner]) == 0 {
			return 0, errors.New("missing or mismatched frozen historical receipt")
		}
		for _, claim := range plan.Claims[receipt.Owner] {
			if _, ok := receipt.Historical.Aliases[claim.Email]; !ok {
				return 0, errors.New("frozen historical alias missing")
			}
		}
		seen[receipt.Owner] = true
		snapshots = append(snapshots, *receipt.Historical)
	}
	return FrozenHistoricalUsage(plan.AccountingRoots, snapshots)
}

// FrozenHistoricalUsage folds the complete legacy accounting tree after every
// physical member is fenced and drained. It rejects missing, multiply imported
// or cyclic paths instead of guessing, dropping usage or granting fresh credit.
// Independent roots may represent device aliases of one shared subscription.
// A control-only root's snapshot comes from the trusted master adapter, not an
// unsigned value supplied by a browser.
func FrozenHistoricalUsage(roots []LegacyRoot, snapshots []LegacySnapshot) (int64, error) {
	if len(roots) == 0 || len(snapshots) == 0 {
		return 0, errors.New("historical accounting scope is empty")
	}
	type address struct{ owner, alias string }
	values := map[address]LegacyAliasSnapshot{}
	owners := map[string]bool{}
	for _, snapshot := range snapshots {
		if snapshot.Owner == "" || owners[snapshot.Owner] || len(snapshot.Aliases) == 0 {
			return 0, errors.New("duplicate or empty historical member")
		}
		owners[snapshot.Owner] = true
		for alias, value := range snapshot.Aliases {
			if alias == "" || value.Total.Up < 0 || value.Total.Down < 0 {
				return 0, errors.New("invalid historical counter")
			}
			if _, err := add(value.Total.Up, value.Total.Down); err != nil {
				return 0, err
			}
			values[address{snapshot.Owner, alias}] = value
		}
	}
	visited := map[address]bool{}
	var visit func(address) (LegacyCounter, error)
	visit = func(key address) (LegacyCounter, error) {
		value, exists := values[key]
		if !exists {
			return LegacyCounter{}, errors.New("historical child snapshot missing")
		}
		if visited[key] {
			return LegacyCounter{}, errors.New("historical alias has multiple parents or a cycle")
		}
		visited[key] = true
		var importedUp, importedDown, childUp, childDown int64
		for _, link := range value.Imports {
			if link.Owner == "" || link.Alias == "" || link.Counter.Up < 0 || link.Counter.Down < 0 {
				return LegacyCounter{}, errors.New("invalid imported baseline")
			}
			var err error
			importedUp, err = add(importedUp, link.Counter.Up)
			if err != nil {
				return LegacyCounter{}, err
			}
			importedDown, err = add(importedDown, link.Counter.Down)
			if err != nil {
				return LegacyCounter{}, err
			}
			child, err := visit(address{link.Owner, link.Alias})
			if err != nil {
				return LegacyCounter{}, err
			}
			// A lower child snapshot can mean an unacknowledged legacy reset.
			// Its epoch cannot be reconstructed by subtracting counters: doing
			// so would erase already-billed history. Resolve that reset first.
			raw := values[address{link.Owner, link.Alias}].Total
			if raw.Up < link.Counter.Up || raw.Down < link.Counter.Down || child.Up < link.Counter.Up || child.Down < link.Counter.Down {
				return LegacyCounter{}, errors.New("historical child regressed; reconcile its reset before enrollment")
			}
			childUp, err = add(childUp, child.Up)
			if err != nil {
				return LegacyCounter{}, err
			}
			childDown, err = add(childDown, child.Down)
			if err != nil {
				return LegacyCounter{}, err
			}
		}
		if importedUp > value.Total.Up || importedDown > value.Total.Down {
			return LegacyCounter{}, errors.New("imported baseline exceeds authoritative total")
		}
		up, err := add(value.Total.Up-importedUp, childUp)
		if err != nil {
			return LegacyCounter{}, err
		}
		down, err := add(value.Total.Down-importedDown, childDown)
		if err != nil {
			return LegacyCounter{}, err
		}
		return LegacyCounter{Up: up, Down: down}, nil
	}
	var billed int64
	for _, root := range roots {
		counter, err := visit(address{root.Owner, root.Alias})
		if err != nil {
			return 0, err
		}
		billed, err = add(billed, counter.Up)
		if err != nil {
			return 0, err
		}
		billed, err = add(billed, counter.Down)
		if err != nil {
			return 0, err
		}
	}
	if len(visited) != len(values) {
		return 0, errors.New("historical member is outside the authoritative accounting tree")
	}
	return billed, nil
}
