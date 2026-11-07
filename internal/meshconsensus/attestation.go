package meshconsensus

import (
	"errors"
	"sync"

	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

// This journal is independent of Raft's restorable log/snapshot directory.
// Restoring an older Raft snapshot must not permit a member to attest a second
// value for a version it has already signed. It records no billable traffic.
type attestationGuard struct {
	mu    sync.Mutex
	store *raftboltdb.BoltStore
}

func (g *attestationGuard) remember(u quotaescrow.PolicyUpdate) error {
	if g == nil || g.store == nil {
		return errors.New("independent attestation journal unavailable")
	}
	u.Votes = nil
	u.Signature = nil
	slot := "policy/" + digest([]any{u.Next.ControlEpoch, u.Next.Subscription, u.Next.Version})
	hash := digest(u)
	g.mu.Lock()
	defer g.mu.Unlock()
	old, err := g.store.Get([]byte(slot))
	if err == nil {
		if string(old) != hash {
			return errors.New("restored control state conflicts with a previously attested policy")
		}
		return nil
	}
	if !errors.Is(err, raftboltdb.ErrKeyNotFound) {
		return err
	}
	// Bolt's default full synchronization durably persists the value BEFORE the
	// signature can leave the node, including when the HTTP response is lost.
	return g.store.Set([]byte(slot), []byte(hash))
}
func (g *attestationGuard) close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_ = g.store.Close()
}

func (n *Node) Attest(u quotaescrow.PolicyUpdate) ([]byte, error) {
	signature, err := n.FSM.attest(u, n.Owner, n.Key)
	if err != nil {
		return nil, err
	}
	if err := n.guard.remember(u); err != nil {
		return nil, err
	}
	return signature, nil
}
