package xray

import (
	"context"
	"errors"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/xray/meshgate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func IsUserGateUnsupported(err error) bool { return status.Code(err) == codes.Unimplemented }

// ReconcileUserGates fences live streams, unlike merely removing credentials.
// The caller supplies the full local deny set and serializes decisions with
// durable quota updates. Unimplemented/error is NOT permission to admit users.
// Never call this for ordinary legacy disable operations or unenrolled panels.
func (x *XrayAPI) ReconcileUserGates(ctx context.Context, blocked []string) error {
	return x.updateUserGates(ctx, "mesh", func([]string) []string { return blocked })
}

// ReconcileConfigGates closes removed users, while preserving independent mesh
// gates and not interrupting a credential edit that retains the same email.
func (x *XrayAPI) ReconcileConfigGates(ctx context.Context, previous, active []string) error {
	return x.updateUserGates(ctx, "config", func(current []string) []string {
		blocked := make(map[string]bool)
		for _, email := range current {
			blocked[email] = true
		}
		for _, email := range previous {
			blocked[email] = true
		}
		for _, email := range active {
			delete(blocked, email)
		}
		result := make([]string, 0, len(blocked))
		for email := range blocked {
			result = append(result, email)
		}
		return result
	})
}

func (x *XrayAPI) updateUserGates(ctx context.Context, scope string, desired func([]string) []string) error {
	if x.grpcClient == nil {
		return errors.New("core API unavailable")
	}
	current := new(meshgate.State)
	if err := x.grpcClient.Invoke(ctx, "/xray.app.stats.command.StatsService/GetUserGates", &meshgate.GetRequest{Scope: scope}, current); err != nil {
		return err
	}
	if current.Instance == "" || current.Scope != scope {
		return errors.New("core returned no gate instance")
	}
	want := slices.Clone(desired(current.BlockedEmails))
	slices.Sort(want)
	want = slices.Compact(want)
	have := slices.Clone(current.BlockedEmails)
	slices.Sort(have)
	if slices.Equal(want, have) {
		return nil
	}
	if current.Revision == ^uint64(0) {
		return errors.New("core gate revision exhausted")
	}
	req := &meshgate.ReplaceRequest{Instance: current.Instance, Revision: current.Revision + 1, BlockedEmails: want, Scope: scope}
	ack := new(meshgate.State)
	if err := x.grpcClient.Invoke(ctx, "/xray.app.stats.command.StatsService/ReplaceUserGates", req, ack); err != nil {
		return err
	}
	slices.Sort(ack.BlockedEmails)
	if ack.Instance != req.Instance || ack.Revision != req.Revision || ack.Scope != scope || !slices.Equal(want, ack.BlockedEmails) {
		return errors.New("core gate changed during reconciliation")
	}
	return nil
}
