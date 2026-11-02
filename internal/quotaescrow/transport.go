package quotaescrow

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SyncAttempt must return success only after verifying the destination's signed
// receipt and durably merging its rows. A relay's HTTP 200 is not an ACK.
// Retries carry cumulative signed rows, never an increment that can be rebilled.
type SyncAttempt func(context.Context, string, string, []SignedRow) error

type SyncTransport struct {
	Direct SyncAttempt
	Relay  SyncAttempt
	// Egress is wired solely to accounting-sync, not the general panel proxy.
	Egress         SyncAttempt
	AttemptTimeout time.Duration
	MaxRelays      int
}

// Sync always tries direct first, even after a successful fallback on a previous
// cycle. Relay IDs come from authenticated membership, never request URLs.
func (t SyncTransport) Sync(ctx context.Context, destination string, relays []string, rows []SignedRow) (string, error) {
	if destination == "" {
		return "", errors.New("missing destination")
	}
	timeout := t.AttemptTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	maxRelays := t.MaxRelays
	if maxRelays <= 0 || maxRelays > 8 {
		maxRelays = 8
	}
	var failures []error
	attempt := func(kind, peer string, send SyncAttempt) bool {
		if send == nil {
			return false
		}
		if ctx.Err() != nil {
			return false
		}
		child, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// An adapter cannot mutate the snapshot subsequently sent by a fallback.
		err := send(child, destination, peer, clone(rows))
		if err == nil && child.Err() == nil {
			return true
		}
		if err == nil {
			err = child.Err()
		}
		failures = append(failures, fmt.Errorf("%s: %w", kind, err))
		return false
	}
	if attempt("direct", destination, t.Direct) {
		return "direct", nil
	}
	seen := map[string]bool{destination: true}
	count := 0
	for _, relay := range relays {
		if relay == "" || seen[relay] {
			continue
		}
		seen[relay] = true
		if count >= maxRelays {
			break
		}
		count++
		if attempt("relay", relay, t.Relay) {
			return "relay", nil
		}
	}
	if attempt("egress", destination, t.Egress) {
		return "egress", nil
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if len(failures) == 0 {
		return "", errors.New("no accounting transport available")
	}
	return "", errors.Join(failures...)
}
