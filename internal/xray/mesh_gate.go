package xray

import (
	"context"
	"errors"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/xray/meshgate"
)

// ReconcileUserGates fences live streams, unlike merely removing credentials.
// The caller supplies the full local deny set and serializes decisions with
// durable quota updates. Unimplemented/error is NOT permission to admit users.
// Never call this for ordinary legacy disable operations or unenrolled panels.
func (x *XrayAPI) ReconcileUserGates(ctx context.Context, blocked []string) error {
	if x.grpcClient == nil {
		return errors.New("core API unavailable")
	}
	current := new(meshgate.State)
	if err := x.grpcClient.Invoke(ctx, "/xray.app.stats.command.StatsService/GetUserGates", &meshgate.GetRequest{}, current); err != nil {
		return err
	}
	if current.Instance == "" {
		return errors.New("core returned no gate instance")
	}
	want := slices.Clone(blocked)
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
	req := &meshgate.ReplaceRequest{Instance: current.Instance, Revision: current.Revision + 1, BlockedEmails: want}
	ack := new(meshgate.State)
	if err := x.grpcClient.Invoke(ctx, "/xray.app.stats.command.StatsService/ReplaceUserGates", req, ack); err != nil {
		return err
	}
	slices.Sort(ack.BlockedEmails)
	if ack.Instance != req.Instance || ack.Revision != req.Revision || !slices.Equal(want, ack.BlockedEmails) {
		return errors.New("core gate changed during reconciliation")
	}
	return nil
}
