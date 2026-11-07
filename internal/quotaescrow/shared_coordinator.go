package quotaescrow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"
)

// resumeShared attempts every member even when an earlier member is offline.
// The immutable update was journaled before any delivery. Offline targets are
// retried by recovery, and any already updated peer can relay its certificates.
func (c *Coordinator) resumeShared(ctx context.Context, job *ControlJob, plan ControlPlan, prior Policy, target ControlTarget, ack map[string]bool) (Policy, bool, error) {
	var next Policy
	if json.Unmarshal([]byte(job.PolicyJSON), &next) != nil || next.Version != prior.Version+1 || next.Epoch != prior.Epoch || next.Limit != target.Limit || next.ExpiresAt != target.ExpiresAt || next.Disabled != target.Disabled || next.Unlimited != target.Unlimited {
		return next, false, errors.New("invalid shared coordinator policy")
	}
	updates, err := decodeUpdates(job.UpdatesJSON)
	if err != nil || len(updates) == 0 {
		return next, false, errors.New("missing shared certificate chain")
	}
	last := updates[len(updates)-1]
	if last.ID != plan.ID || last.Kind != plan.Kind || !reflect.DeepEqual(last.Next, next) {
		return next, false, errors.New("shared operation mismatch")
	}
	if err := VerifyPolicyUpdate(prior, last); err != nil {
		return next, false, err
	}
	if c.UpdatePolicy == nil {
		return next, false, errors.New("shared policy transport unavailable")
	}
	// An offline member may have missed several operations. Deliver the latest
	// complete chain once; never briefly reopen at an obsolete intermediate reset.
	latest := next
	var candidates []ControlJob
	if err := c.DB.Where("subscription = ? AND policy_json <> ?", next.Subscription, "").Find(&candidates).Error; err != nil {
		return next, false, err
	}
	for _, candidate := range candidates {
		var p Policy
		if json.Unmarshal([]byte(candidate.PolicyJSON), &p) != nil {
			return next, false, errors.New("invalid policy journal")
		}
		if p.Version <= latest.Version {
			continue
		}
		chain, err := decodeUpdates(candidate.UpdatesJSON)
		if err != nil || len(chain) < len(updates) || !SamePolicyUpdates(chain[:len(updates)], updates) {
			return next, false, errors.New("forked policy journal")
		}
		base := latest
		for _, u := range chain[len(updates):] {
			if err := VerifyPolicyUpdate(base, u); err != nil {
				return next, false, err
			}
			base = u.Next
		}
		if !reflect.DeepEqual(base, p) {
			return next, false, errors.New("incomplete policy journal")
		}
		latest, updates = p, chain
	}
	owners := make([]string, 0, len(next.Keys))
	for owner := range next.Keys {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	var failures []error
	for _, owner := range owners {
		if ack[owner] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return next, false, errors.Join(err, errors.Join(failures...))
		}
		child, cancel := context.WithTimeout(ctx, 5*time.Second)
		receipt, err := c.UpdatePolicy(child, owner, PolicyUpdateRequest{Subscription: next.Subscription, Updates: updates})
		cancel()
		if err == nil {
			err = VerifyPolicyReceipt(receipt, latest, owner)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		ack[owner] = true
		body, _ := json.Marshal(ack)
		if err := c.save(job, map[string]any{"acknowledged_json": string(body)}); err != nil {
			return next, false, err
		}
	}
	if len(ack) != len(next.Keys) {
		return next, false, errors.Join(failures...)
	}
	if !job.Complete {
		if err := c.save(job, map[string]any{"complete": true}); err != nil {
			return next, false, err
		}
	}
	return next, true, nil
}
