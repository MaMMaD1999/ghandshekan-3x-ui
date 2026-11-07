package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
)

// An operator request specifies the complete mutable quota/expiry/availability
// target. Membership and reset scheduling use their own coordinated operations.
func majorityCommand(kind, id string, input request) (meshconsensus.Command, error) {
	if (kind != "renew" && kind != "reset") || id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n") ||
		input.Subscription == "" || len(input.Subscription) > 512 || input.Previous != "" || len(input.Roots) != 0 {
		return meshconsensus.Command{}, errors.New("majority renew/reset requires a subscription and stable --operation ID, without roots or previous coordinator jobs")
	}
	t := input.Target
	if t.Mode != "shared" || t.Limit < 0 || t.ExpiresAt < 0 || t.ExpiresAt > math.MaxInt64/1000 || (t.Unlimited && t.Limit != 0) || t.Weights != nil || t.ResetSchedule != nil || t.ScheduledAt != 0 {
		return meshconsensus.Command{}, errors.New("majority lifecycle accepts only shared quota, expiry and availability")
	}
	h := sha256.Sum256([]byte(input.Subscription + "\x00" + kind + "\x00" + id))
	return meshconsensus.Command{ID: "operator-" + hex.EncodeToString(h[:]), Subscription: input.Subscription, Kind: kind,
		Patch: &meshconsensus.PolicyPatch{Limit: &t.Limit, ExpiresAt: &t.ExpiresAt, Disabled: &t.Disabled, Unlimited: &t.Unlimited}}, nil
}

func submitMajorityChange(ctx context.Context, owner string, command meshconsensus.Command,
	call func(context.Context, string, string, any, any) error, output io.Writer) error {
	// Print the immutable ID before the first request. After an ambiguous network
	// failure, rerun this same input and --operation; never invent a new reset.
	if _, err := fmt.Fprintln(output, "Operation:", command.ID); err != nil {
		return err
	}
	var result meshconsensus.Result
	if err := call(ctx, owner, "submit", command, &result); err != nil {
		return fmt.Errorf("operation outcome is unconfirmed; retry the same request and --operation: %w", err)
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	if result.Update == nil || result.Update.Next.Subscription != command.Subscription || result.Update.Kind != command.Kind || result.Update.Next.Version < 2 {
		return errors.New("missing or mismatched majority result")
	}
	// The authenticated local controller replies only after Raft commitment.
	// It applies the latest certified policy through its normal background worker.
	// A commit does not claim that every disconnected member has applied it.
	return json.NewEncoder(output).Encode(map[string]any{"operation": command.ID,
		"majorityCommitted": true, "version": result.Update.Next.Version,
		"generation": result.Update.Next.ResetGeneration, "applicationPending": true})
}
