package meshconsensus

import (
	"errors"
	"reflect"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

// Only mutable policy values are retained in an administrator's retry receipt.
// Copying all peer keys, grants, and schedule definitions for every request
// caused both FSM memory and snapshots to grow with redundant membership data.
type policyValue struct {
	ID, Kind, PreviousHash string
	Version, Generation    uint64
	Limit, ExpiresAt       int64
	AlreadyBilled          int64
	Disabled, Unlimited    bool
	ScheduledThrough       int64
}

func compactResult(c Command, out Result) applied {
	a := applied{Hash: digest(c), Result: out}
	if out.Update != nil {
		u, p := out.Update, out.Update.Next
		a.Subscription = p.Subscription
		a.Value = &policyValue{ID: u.ID, Kind: u.Kind, PreviousHash: u.PreviousHash, Version: p.Version, Generation: p.ResetGeneration, Limit: p.Limit, ExpiresAt: p.ExpiresAt, AlreadyBilled: p.AlreadyBilled, Disabled: p.Disabled, Unlimited: p.Unlimited, ScheduledThrough: p.ScheduledThrough}
		a.Result.Update = nil
	}
	return a
}

func (a applied) result(subscriptions map[string]subscription) Result {
	if a.Value == nil {
		return copyJSON(a.Result)
	}
	s, ok := subscriptions[a.Subscription]
	if !ok {
		return Result{Error: "operation receipt lost its subscription"}
	}
	v := a.Value
	p := copyJSON(s.Base.Policy)
	p.Version, p.ResetGeneration = v.Version, v.Generation
	p.Limit, p.ExpiresAt, p.AlreadyBilled = v.Limit, v.ExpiresAt, v.AlreadyBilled
	p.Disabled, p.Unlimited, p.ScheduledThrough = v.Disabled, v.Unlimited, v.ScheduledThrough
	return Result{Update: &quotaescrow.PolicyUpdate{ID: v.ID, Kind: v.Kind, PreviousHash: v.PreviousHash, Next: p}}
}

// Timer IDs have a reserved namespace and are derived from the subscription
// and exact boundary. A compact watermark can reject old timer replays forever
// without keeping one request receipt for every hour of every subscription.
func ScheduledOperationID(subscription string, at int64) string {
	return "timer-" + digest([]any{subscription, at})
}

func validateTimerCommand(c Command) error {
	if c.Kind != "scheduled-reset" {
		if strings.HasPrefix(c.ID, "timer-") {
			return errors.New("timer operation namespace is reserved")
		}
		return nil
	}
	if c.Patch == nil || c.Patch.ScheduledAt <= 0 || c.ID != ScheduledOperationID(c.Subscription, c.Patch.ScheduledAt) || c.Registration != nil || c.ExpectedHash != "" || !reflect.DeepEqual(c.Target, quotaescrow.ControlTarget{}) || !reflect.DeepEqual(*c.Patch, PolicyPatch{ScheduledAt: c.Patch.ScheduledAt}) {
		return errors.New("invalid canonical timer operation")
	}
	return nil
}

func verifyCommittedAdvance(previous quotaescrow.Policy, u quotaescrow.PolicyUpdate) error {
	if u.Next.Version > previous.Version && u.Next.Version-previous.Version > 1 {
		return quotaescrow.VerifyPolicyCheckpointShape(previous, u)
	}
	return quotaescrow.VerifyPolicyShape(previous, u)
}
