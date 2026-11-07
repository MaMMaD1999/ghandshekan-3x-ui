package quotaescrow

import (
	"encoding/hex"
	"errors"
	"reflect"
	"time"
)

// VerifyPolicyCheckpointShape validates a jump to a committed majority policy.
// It is NOT authorization by itself. Every receiving path must also verify the
// majority certificate with VerifyPolicyUpdate. An authority-only policy still
// needs its complete consecutive chain.
//
// Membership, lifetime epoch, and initial billing baseline cannot be replaced.
// The reset generation tells a returning member whether to cut over its local
// lifetime baseline once, regardless of how many reset periods it missed.
func VerifyPolicyCheckpointShape(previous Policy, u PolicyUpdate) error {
	if _, err := New(previous); err != nil {
		return err
	}
	if _, err := New(u.Next); err != nil {
		return err
	}
	if previous.ControlEpoch == "" || previous.Version == 0 || u.Next.Version <= previous.Version || u.ID == "" || len(u.ID) > 128 || (u.Kind != "renew" && u.Kind != "reset" && u.Kind != "scheduled-reset" && u.Kind != "alias") {
		return errors.New("invalid majority policy checkpoint")
	}
	if b, err := hex.DecodeString(u.PreviousHash); err != nil || len(b) != 32 {
		return errors.New("invalid checkpoint predecessor hash")
	}
	steps := u.Next.Version - previous.Version
	if u.Next.ResetGeneration < previous.ResetGeneration || u.Next.ResetGeneration-previous.ResetGeneration > steps || u.Next.ScheduledThrough < previous.ScheduledThrough {
		return errors.New("checkpoint lifecycle counters regressed or skipped impossible generations")
	}
	expected := clone(previous)
	expected.Version = u.Next.Version
	expected.Limit, expected.ExpiresAt = u.Next.Limit, u.Next.ExpiresAt
	expected.Disabled, expected.Unlimited = u.Next.Disabled, u.Next.Unlimited
	expected.ResetGeneration = u.Next.ResetGeneration
	if !reflect.DeepEqual(previous.Aliases, u.Next.Aliases) {
		if err := verifyAliasAdvance(previous, u.Next, false); err != nil {
			return err
		}
		expected.Aliases = clone(u.Next.Aliases)
	}
	if expected.ResetGeneration != previous.ResetGeneration {
		expected.AlreadyBilled = 0
	}
	if u.Next.ScheduledThrough != previous.ScheduledThrough {
		boundary, err := previous.ResetSchedule.Due(time.Unix(u.Next.ScheduledThrough, 0), previous.ScheduledThrough)
		if err != nil || boundary == 0 || boundary != u.Next.ScheduledThrough || u.Next.ResetGeneration == previous.ResetGeneration {
			return errors.New("checkpoint has an invalid scheduled boundary")
		}
		expected.ScheduledThrough = u.Next.ScheduledThrough
	}
	if (u.Kind == "reset" || u.Kind == "scheduled-reset") && u.Next.ResetGeneration == previous.ResetGeneration {
		return errors.New("checkpoint reset did not advance its generation")
	}
	if !reflect.DeepEqual(expected, u.Next) {
		return errors.New("checkpoint changed membership, epoch or billing baseline")
	}
	return nil
}

func compactPolicyHistory(p Policy, updates []PolicyUpdate) []PolicyUpdate {
	if p.ControlEpoch != "" && len(updates) > 1 {
		return updates[len(updates)-1:]
	}
	return updates
}
