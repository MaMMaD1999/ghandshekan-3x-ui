package quotaescrow

import (
	"context"
	"errors"
	"slices"
)

// AliasChanges discovers a new disabled device through the authenticated panel
// topology. Revocation uses the existing signed catalog and needs no live peer.
// A new metering owner requires a distinct accounting-membership transition;
// its identity and historical bytes are never inferred by this API.
func (b PlanBuilder) AliasChanges(ctx context.Context, p Policy, owner, email string, revoke bool) ([]AliasPatch, error) {
	return b.AliasChangesForRoots(ctx, p, owner, email, revoke, nil)
}

func (b PlanBuilder) AliasChangesForRoots(ctx context.Context, p Policy, owner, email string, revoke bool, roots []string) ([]AliasPatch, error) {
	if _, err := New(p); err != nil {
		return nil, err
	}
	if p.Aliases == nil || email == "" || len(email) > 512 {
		return nil, errors.New("device membership requires its enrollment manager and catalog")
	}
	// Revocation uses only the committed catalog and still has to win a fresh
	// majority in the control journal. A disconnected enrollment manager must
	// not prevent the connected majority from removing a stolen session.
	if _, registered := p.ControlKeys[owner]; !registered || (!revoke && p.Manager != owner) {
		return nil, errors.New("device attachment requires its manager; revocation requires a registered controller")
	}
	var patches []AliasPatch
	if revoke {
		for member, aliases := range p.Aliases {
			if a, ok := aliases[email]; ok && !a.Revoked {
				patches = append(patches, AliasPatch{Owner: member, Email: email, ExpectedRevision: a.Revision, Fingerprint: a.Fingerprint, Revoked: true})
			}
		}
	} else {
		if len(roots) == 0 {
			roots = []string{owner}
		}
		if len(roots) > 256 || !slices.Contains(roots, owner) {
			return nil, errors.New("device accounting roots must include its manager")
		}
		queue, seen := slices.Clone(roots), map[string]bool{}
		for len(queue) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			member := queue[0]
			queue = queue[1:]
			if seen[member] || len(seen) >= 256 {
				return nil, errors.New("cyclic or multiply imported device alias")
			}
			seen[member] = true
			if _, ok := p.Keys[member]; !ok {
				return nil, errors.New("device topology contains an unenrolled traffic member")
			}
			inventory, err := b.inventory(ctx, member, []string{email})
			if err != nil {
				return nil, err
			}
			a := inventory.Aliases[0]
			old, exists := p.Aliases[member][email]
			if a.Pending || (a.Subscription != "" && a.Subscription != p.Subscription) || (a.Epoch != "" && a.Epoch != p.Epoch) {
				return nil, errors.New("device alias belongs to another accounting scope or a pending operation")
			}
			if !exists && (a.Enabled || a.LocalBilled != 0 || a.Subscription != "" || a.Epoch != "") {
				return nil, errors.New("new device must be disabled and unused before attachment")
			}
			if exists && old.Fingerprint != a.Claim.Fingerprint {
				return nil, errors.New("credential replacement requires a separate fenced transition")
			}
			if !exists || old.Revoked {
				patches = append(patches, AliasPatch{Owner: member, Email: email, ExpectedRevision: old.Revision, Fingerprint: a.Claim.Fingerprint})
			}
			queue = append(queue, a.Children...)
		}
	}
	if len(patches) == 0 {
		return nil, errors.New("device authorization is already in the requested state")
	}
	slices.SortFunc(patches, func(a, b AliasPatch) int {
		if a.Owner < b.Owner {
			return -1
		}
		if a.Owner > b.Owner {
			return 1
		}
		return 0
	})
	if _, err := DraftAliasChanges(p, "validate-device-plan", patches); err != nil {
		return nil, err
	}
	return patches, nil
}
