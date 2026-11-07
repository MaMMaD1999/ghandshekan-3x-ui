package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

type MeshQuorum struct {
	Node         *meshconsensus.Node
	Wire         *meshconsensus.Wire
	Transport    *meshconsensus.Transport
	Local        *MeshControl
	mu           sync.Mutex
	certificates map[string]quotaescrow.PolicyUpdate
	cursor       int
}

func OpenMeshQuorum(c *MeshConfig, local *MeshControl, trust *tls.Config, direct *http.Client, proxy func() string) (*MeshQuorum, error) {
	if c.ControlEpoch == "" {
		return nil, nil
	}
	tr := meshconsensus.NewTransport(c.Owner)
	wire := &meshconsensus.Wire{Owner: c.Owner, Epoch: c.ControlEpoch, Key: ed25519.PrivateKey(c.PrivateKey), Keys: c.PeerKeys, Peers: c.Peers, Direct: direct}
	wire.Egress = func() (*http.Client, error) {
		address := ""
		if proxy != nil {
			address = proxy()
		}
		if address == "" {
			return nil, errors.New("accounting fallback is unavailable")
		}
		unused, fallback, err := quotaescrow.HTTPClients(trust, address)
		if unused != nil {
			unused.CloseIdleConnections()
		}
		return fallback, err
	}
	tr.Call = wire.Call
	n, err := meshconsensus.Open(meshconsensus.Options{Owner: c.Owner, Epoch: c.ControlEpoch, Directory: filepath.Join(c.StateDir, "consensus"), Keys: c.PeerKeys, Key: ed25519.PrivateKey(c.PrivateKey), Authority: ed25519.PublicKey(c.Authority), Transport: tr, Bootstrap: c.BootstrapControl})
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	n.Call = wire.Call
	wire.SetHandler(func(ctx context.Context, from, kind string, body json.RawMessage) (any, error) {
		if kind == "propose" || kind == "submit" || kind == "attest" || kind == "admit" {
			return n.Handle(ctx, kind, body)
		}
		return tr.Handle(ctx, from, kind, body)
	})
	return &MeshQuorum{Node: n, Wire: wire, Transport: tr, Local: local, certificates: map[string]quotaescrow.PolicyUpdate{}}, nil
}
func (q *MeshQuorum) Close() {
	if q == nil {
		return
	}
	q.Node.Close()
	_ = q.Transport.Close()
}

func (q *MeshQuorum) certified(ctx context.Context, sub string, after, required uint64) ([]quotaescrow.PolicyUpdate, error) {
	// A follower may return the leader's commit result before its own FSM has
	// applied the corresponding entry. Wait for that exact committed version.
	for {
		p, err := q.Node.FSM.Policy(sub)
		if err == nil && p.Version >= required {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	base, err := q.Node.FSM.Base(sub)
	if err != nil {
		return nil, err
	}
	updates, err := q.Node.FSM.Updates(sub, 0)
	if err != nil {
		return nil, err
	}
	var out []quotaescrow.PolicyUpdate
	for _, u := range updates {
		if u.Next.Version > after {
			hash := quotaescrow.PolicyHash(u.Next)
			q.mu.Lock()
			cert, ok := q.certificates[hash]
			q.mu.Unlock()
			if !ok {
				cert, err = q.Node.Certify(ctx, base, u)
				if err != nil {
					return nil, err
				}
				q.mu.Lock()
				q.certificates[hash] = cert
				q.mu.Unlock()
			}
			out = append(out, cert)
		}
		base = u.Next
	}
	return out, nil
}
func (q *MeshQuorum) synchronize(ctx context.Context, sub string, required uint64) error {
	l, err := quotaescrow.NewStore(q.Local.DB).Load(sub)
	if err != nil {
		return err
	}
	p := l.Policy()
	if p.ControlEpoch != q.Node.Epoch {
		return errors.New("local control membership differs")
	}
	updates, err := q.certified(ctx, sub, p.Version, required)
	if err != nil {
		return err
	}
	if len(updates) == 0 {
		return nil
	}
	return q.Local.ApplySharedUpdates(ctx, sub, updates)
}

func (q *MeshQuorum) Queue(ctx context.Context, sub, kind, key string, limit, expiry *int64, availability ...MeshAvailability) (MeshOperationResult, error) {
	var out MeshOperationResult
	id, err := meshOperationID(sub, kind, key)
	if err != nil {
		return out, err
	}
	if len(availability) > 1 {
		return out, errors.New("invalid availability options")
	}
	patch := &meshconsensus.PolicyPatch{Limit: limit, ExpiresAt: expiry}
	if len(availability) == 1 {
		patch.Disabled = availability[0].Disabled
		patch.Unlimited = availability[0].Unlimited
	}
	// Check enrollment locally before submitting any administrative command.
	l, err := quotaescrow.NewStore(q.Local.DB).Load(sub)
	if err != nil {
		return out, err
	}
	if l.Policy().ControlEpoch != q.Node.Epoch {
		return out, errors.New("subscription is not enrolled in this control cluster")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result, err := q.Node.Execute(bounded, meshconsensus.Command{ID: id, Subscription: sub, Kind: kind, Patch: patch})
	if err != nil {
		return out, err
	}
	if result.Update == nil {
		return out, errors.New("missing committed policy result")
	}
	out = MeshOperationResult{Operation: id, Pending: true}
	return out, q.synchronize(bounded, sub, result.Update.Next.Version)
}

func (q *MeshQuorum) SyncCycle(ctx context.Context) error {
	var records []quotaescrow.Record
	if err := q.Local.DB.Select("subscription", "policy_json").Order("subscription").Find(&records).Error; err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	work := 0
	for i := 0; i < len(records) && work < 8; i++ {
		index := q.cursor % len(records)
		q.cursor = (index + 1) % len(records)
		var p quotaescrow.Policy
		if json.Unmarshal([]byte(records[index].PolicyJSON), &p) != nil {
			return errors.New("invalid local mesh policy")
		}
		if p.ControlEpoch != q.Node.Epoch {
			continue
		}
		latest, err := q.Node.FSM.Policy(p.Subscription)
		if err != nil || latest.Version <= p.Version {
			continue
		}
		work++
		if err := q.synchronize(ctx, p.Subscription, latest.Version); err != nil {
			return err
		}
	}
	return nil
}
