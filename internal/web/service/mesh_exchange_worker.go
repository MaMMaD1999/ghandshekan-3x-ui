package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// MeshExchangeWorker has no authority to allocate/reclaim credit. It only
// propagates signed cumulative rows and verifies the destination's receipt.
type MeshExchangeWorker struct {
	DB               *gorm.DB
	Owner            string
	Key              ed25519.PrivateKey
	Peers            map[string]string
	Trust            *tls.Config
	Direct           *http.Client
	AccountingProxy  func() string
	Checkpoint       func() error
	ScopedCheckpoint func(string) error
	ApplyUpdates     func(context.Context, string, []quotaescrow.PolicyUpdate) error
	mu               sync.Mutex
	cursor           int
}

func (w *MeshExchangeWorker) Handler() http.Handler {
	return (quotaescrow.HTTPExchange{Store: quotaescrow.NewStore(w.DB), Owner: w.Owner, Key: w.Key, Peers: w.Peers, Client: w.Direct, Checkpoint: w.Checkpoint, ScopedCheckpoint: w.ScopedCheckpoint, ApplyUpdates: w.ApplyUpdates}).Handler()
}

// Cycle bounds work and retains a round-robin cursor so unreachable peers do
// not starve subscriptions near the end of a large registry. The local worker
// runs independently; this cycle never holds its enforcement lock.
func (w *MeshExchangeWorker) Cycle(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.DB == nil || len(w.Key) != ed25519.PrivateKeySize || w.Direct == nil {
		return errors.New("mesh exchange not configured")
	}
	var subscriptions []string
	if err := w.DB.Model(&model.MeshBinding{}).Where("owner = ?", w.Owner).Distinct("subscription").Order("subscription").Pluck("subscription", &subscriptions).Error; err != nil {
		return err
	}
	if len(subscriptions) == 0 {
		return nil
	}
	cycle, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	jobs := make(chan string)
	var workers sync.WaitGroup
	var failuresMu sync.Mutex
	var failures []error
	for n := 0; n < min(4, len(subscriptions)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				if v := recover(); v != nil {
					failuresMu.Lock()
					failures = append(failures, fmt.Errorf("mesh exchange task panic: %v", v))
					failuresMu.Unlock()
					cancel()
				}
			}()
			for subscription := range jobs {
				store := quotaescrow.NewStore(w.DB)
				exchange := quotaescrow.HTTPExchange{Store: store, Owner: w.Owner, Key: w.Key, Subscription: subscription, Peers: w.Peers, Client: w.Direct, Checkpoint: w.Checkpoint, ScopedCheckpoint: w.ScopedCheckpoint, ApplyUpdates: w.ApplyUpdates}
				transport := quotaescrow.SyncTransport{Direct: exchange.Attempt, Relay: exchange.Attempt, AttemptTimeout: 2 * time.Second, MaxRelays: 4}
				transport.Egress = func(c context.Context, destination, via string, rows []quotaescrow.SignedRow) error {
					if w.AccountingProxy == nil {
						return errors.New("accounting fallback is not configured")
					}
					address := w.AccountingProxy()
					if address == "" {
						return errors.New("accounting fallback is unavailable")
					}
					direct, fallback, err := quotaescrow.HTTPClients(w.Trust, address)
					if err != nil {
						return err
					}
					defer direct.CloseIdleConnections()
					defer fallback.CloseIdleConnections()
					copy := exchange
					copy.Client = fallback
					return copy.Attempt(c, destination, via, rows)
				}
				results, err := store.SyncSubscription(cycle, subscription, w.Owner, transport)
				failuresMu.Lock()
				if err != nil && len(failures) < 8 {
					failures = append(failures, err)
				}
				for _, result := range results {
					if result.Err != nil && len(failures) < 8 {
						failures = append(failures, result.Err)
					}
				}
				failuresMu.Unlock()
			}
		}()
	}
	for i := 0; i < len(subscriptions); i++ {
		index := w.cursor % len(subscriptions)
		select {
		case jobs <- subscriptions[index]:
			w.cursor = (index + 1) % len(subscriptions)
		case <-cycle.Done():
			close(jobs)
			workers.Wait()
			return errors.Join(cycle.Err(), errors.Join(failures...))
		}
	}
	close(jobs)
	workers.Wait()
	return errors.Join(failures...)
}
