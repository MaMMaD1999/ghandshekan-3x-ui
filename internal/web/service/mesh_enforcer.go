package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
)

// MeshEnforcer runs local settlement independently of network exchanges. The
// supervisor must stop admission if Fence fails; returning an error is never
// permission to leave an unconfirmed fence open. Provisioning must serialize
// enrollment with this cycle and fence new aliases before persisting bindings.
type MeshEnforcer struct {
	DB          *gorm.DB
	KeyForOwner func(string) (ed25519.PrivateKey, error)
	Fence       func(context.Context, []string) error
	Checkpoint  func() error
	mu          sync.Mutex
	known       map[string]bool
}

// MeshFenceError means the runtime barrier was not confirmed. The supervisor
// must stop the managed runtime, rather than merely logging an accounting error.
type MeshFenceError struct{ Err error }

func (e *MeshFenceError) Error() string { return "mesh runtime fence unconfirmed: " + e.Err.Error() }
func (e *MeshFenceError) Unwrap() error { return e.Err }

// ReconcileCurrent uses the durable checked clock. Even when the clock cannot be
// trusted, settle actual traffic and fence enrolled aliases; do not renew time.
func (e *MeshEnforcer) ReconcileCurrent(ctx context.Context) error {
	if e.DB == nil {
		return &MeshFenceError{Err: errors.New("mesh database is not configured")}
	}
	var count int64
	if e.DB != nil {
		if err := e.DB.Model(&model.MeshBinding{}).Count(&count).Error; err != nil {
			return &MeshFenceError{Err: err}
		}
		if count == 0 {
			return e.Reconcile(ctx, 0)
		}
	}
	now, err := checkedMeshUnix(e.DB)
	if err != nil {
		return errors.Join(err, e.Reconcile(ctx, -1))
	}
	return e.Reconcile(ctx, now)
}

// Reconcile never uses peer availability as a reason to free spending rights.
// now must come from the supervisor's checked clock, not an untrusted request.
func (e *MeshEnforcer) Reconcile(ctx context.Context, now int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.DB == nil || e.Fence == nil {
		return &MeshFenceError{Err: errors.New("mesh enforcement is not configured")}
	}
	if e.Checkpoint != nil {
		if err := e.Checkpoint(); err != nil {
			return &MeshFenceError{Err: err}
		}
	}
	if e.known == nil {
		e.known = map[string]bool{}
	}
	var bindings []model.MeshBinding
	if err := e.DB.Find(&bindings).Error; err != nil {
		if len(e.known) == 0 {
			// Without a known admission set, replacing the core's fence with an
			// empty list would reopen previously blocked sessions after restart.
			return &MeshFenceError{Err: err}
		}
		return errors.Join(err, e.apply(ctx, e.known))
	}
	for _, b := range bindings {
		e.known[b.Email] = true
	}
	pending, pendingErr := meshPendingAliases(e.DB)
	if pendingErr != nil {
		return &MeshFenceError{Err: pendingErr}
	}
	for email := range pending {
		e.known[email] = true
	}
	if len(e.known) == 0 {
		return nil
	}
	failures, settleErr := SettleMeshMeters(e.DB, e.KeyForOwner)
	blocked, decisionErr := MeshBlockedEmails(e.DB, now)
	if blocked == nil {
		blocked = map[string]bool{}
	}
	if settleErr != nil || decisionErr != nil {
		// A global read/signing failure cannot turn a previous deny into allow.
		for email := range e.known {
			blocked[email] = true
		}
	} else {
		for _, b := range bindings {
			if failures[b.Subscription] != nil {
				blocked[b.Email] = true
			}
		}
		// A binding disappearing does not itself authorize reopening its alias.
		present := map[string]bool{}
		for email := range pending {
			present[email] = true
		}
		for _, b := range bindings {
			present[b.Email] = true
		}
		for email := range e.known {
			if !present[email] {
				blocked[email] = true
			}
		}
	}
	if e.Checkpoint != nil {
		if err := e.Checkpoint(); err != nil {
			return &MeshFenceError{Err: err}
		}
	}
	errList := []error{settleErr, decisionErr, e.apply(ctx, blocked)}
	for _, err := range failures {
		errList = append(errList, err)
	}
	return errors.Join(errList...)
}

func (e *MeshEnforcer) apply(ctx context.Context, blocked map[string]bool) error {
	emails := make([]string, 0, len(blocked))
	for email, deny := range blocked {
		if deny {
			emails = append(emails, email)
		}
	}
	slices.Sort(emails)
	if err := e.Fence(ctx, emails); err != nil {
		return &MeshFenceError{Err: err}
	}
	return nil
}
