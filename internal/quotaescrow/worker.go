package quotaescrow

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// PeerResult reports delivery, not consumption. Never use it to release a
// disconnected peer's grant or to add traffic to a billing counter.
type PeerResult struct {
	Peer string
	Path string
	Err  error
}

// SyncSubscription exchanges committed rows with every other authenticated
// member. There is no privileged master destination. A dead peer does not hold
// the remaining peers behind its direct/relay timeouts. The caller must run
// this network work independently of local metering and runtime enforcement.
func (s *Store) SyncSubscription(ctx context.Context, subscription, owner string, transport SyncTransport) ([]PeerResult, error) {
	l, err := s.Load(subscription)
	if err != nil {
		return nil, err
	}
	if _, ok := l.policy.Keys[owner]; !ok {
		return nil, errors.New("local owner is not a member")
	}
	peers := make([]string, 0, len(l.policy.Keys)-1)
	for id := range l.policy.Keys {
		if id != owner {
			peers = append(peers, id)
		}
	}
	sort.Strings(peers)
	results := make([]PeerResult, len(peers))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < min(4, len(peers)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				result := PeerResult{Peer: peers[i]}
				// Refresh after earlier receipts so newly learned rows propagate in
				// this cycle where possible; cumulative merging makes retries safe.
				current, loadErr := s.Load(subscription)
				if loadErr != nil {
					result.Err = loadErr
				} else if current.policy.Epoch != l.policy.Epoch {
					result.Err = ErrEpoch
				} else {
					result.Path, result.Err = transport.Sync(ctx, peers[i], peers, current.Snapshot())
				}
				results[i] = result
			}
		}()
	}
	for i := range peers {
		select {
		case jobs <- i:
		case <-ctx.Done():
			for j := i; j < len(peers); j++ {
				results[j] = PeerResult{Peer: peers[j], Err: ctx.Err()}
			}
			close(jobs)
			workers.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	workers.Wait()
	return results, ctx.Err()
}

// RunSync starts immediately, then waits after each completed cycle. It never
// overlaps cycles or accumulates a backlog when the network is unavailable.
// cycle must honor ctx; shutdown waits for it rather than leaving a detached
// goroutine that could write stale state after the panel restarts.
func RunSync(ctx context.Context, interval time.Duration, cycle func(context.Context)) error {
	if interval <= 0 || cycle == nil {
		return errors.New("invalid sync schedule")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		cycle(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
