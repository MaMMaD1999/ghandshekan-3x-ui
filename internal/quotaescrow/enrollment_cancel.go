package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

var ErrEnrollmentCanceled = errors.New("uncommitted enrollment canceled; retry discovery after legacy work completes")

// Cancel only before a policy has even been produced. Persist this terminal
// decision before contacting peers; no recovery worker can later commit it.
// Receipts and historical counters remain intact. Cancellation never resets,
// renews or releases a previously enrolled account.
func (c *Coordinator) CancelEnrollment(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var job ControlJob
	if err := c.DB.First(&job, "id = ?", id).Error; err != nil {
		return err
	}
	if !job.CancelRequested {
		var plan ControlPlan
		if json.Unmarshal([]byte(job.PlanJSON), &plan) != nil || plan.Kind != "enroll" || plan.Validate() != nil || job.Complete || job.PolicyJSON != "" {
			return errors.New("cannot cancel enrollment after policy decision")
		}
		if err := c.save(&job, map[string]any{"cancel_requested": true}); err != nil {
			return err
		}
		job.CancelRequested = true
	}
	return c.resumeEnrollmentCancellation(ctx, &job)
}

func (c *Coordinator) resumeEnrollmentCancellation(ctx context.Context, job *ControlJob) error {
	var plan ControlPlan
	var keys map[string][]byte
	var acknowledgements map[string]ControlReceipt
	if !job.CancelRequested || job.PolicyJSON != "" || json.Unmarshal([]byte(job.PlanJSON), &plan) != nil || plan.Validate() != nil || plan.Kind != "enroll" || json.Unmarshal([]byte(job.KeysJSON), &keys) != nil || json.Unmarshal([]byte(job.CanceledOwnersJSON), &acknowledgements) != nil {
		return errors.New("invalid durable enrollment cancellation")
	}
	if acknowledgements == nil {
		acknowledgements = map[string]ControlReceipt{}
	}
	owners := make([]string, 0, len(plan.Claims))
	for owner := range plan.Claims {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	for _, owner := range owners {
		ack, exists := acknowledgements[owner]
		if !exists {
			now := time.Now().Unix()
			signed, err := SignControl(ControlCommand{Plan: plan, Operation: "cancel-enrollment", IssuedAt: now - 1, ValidUntil: now + 120}, c.Authority)
			if err != nil {
				return err
			}
			ack, err = c.Call(ctx, owner, signed)
			if err != nil {
				return err
			}
		}
		if ack.Owner != owner {
			return errors.New("cancellation owner mismatch")
		}
		if err := VerifyEnrollmentCancellation(ack, plan, ed25519.PublicKey(keys[owner])); err != nil {
			return err
		}
		if !exists {
			acknowledgements[owner] = ack
			body, _ := json.Marshal(acknowledgements)
			if err := c.save(job, map[string]any{"canceled_owners_json": string(body)}); err != nil {
				return err
			}
		}
	}
	if !job.Complete {
		if err := c.save(job, map[string]any{"complete": true}); err != nil {
			return err
		}
	}
	return ErrEnrollmentCanceled
}
