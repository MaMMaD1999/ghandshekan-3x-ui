package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// ApplySharedUpdates is shared by private control and peer reconciliation.
// Verified policy certificates travel through the existing direct -> relay ->
// explicit accounting fallback. Receiving one never depends on the master.
func (c *MeshControl) ApplySharedUpdates(ctx context.Context, subscription string, updates []quotaescrow.PolicyUpdate) error {
	if c.DB == nil || c.Enforcer == nil || c.Drain == nil || c.Flush == nil || c.Checkpoint == nil || len(c.Key) != ed25519.PrivateKeySize {
		return errors.New("shared lifecycle adapter unavailable")
	}
	check := c.Checkpoint
	if c.ScopedCheckpoint != nil {
		check = func() error { return c.ScopedCheckpoint(subscription) }
	}
	if err := check(); err != nil {
		return err
	}
	needed, err := quotaescrow.NewStore(c.DB).NeedsSharedUpdates(subscription, updates)
	if err != nil || !needed {
		return err
	}
	c.Enforcer.mu.Lock()
	defer c.Enforcer.mu.Unlock()
	if err := check(); err != nil {
		return err
	}
	var current quotaescrow.Record
	if err := c.DB.First(&current, "subscription = ?", subscription).Error; err != nil {
		return err
	}
	var policy quotaescrow.Policy
	if json.Unmarshal([]byte(current.PolicyJSON), &policy) != nil || policy.Version == 0 || !bytes.Equal(policy.Authority, c.Authority) {
		return errors.New("subscription has no matching shared authority")
	}
	var bindings []model.MeshBinding
	if err := c.DB.Where("subscription = ?", subscription).Find(&bindings).Error; err != nil {
		return err
	}
	if len(bindings) == 0 {
		return errors.New("subscription has no local bindings")
	}
	emails := make([]string, 0, len(bindings))
	for _, b := range bindings {
		if b.Owner != c.Owner {
			return errors.New("foreign local subscription binding")
		}
		emails = append(emails, b.Email)
	}
	needed = false
	if err := c.transaction(func(tx *gorm.DB) error {
		var err error
		needed, err = quotaescrow.NewStore(tx).BeginSharedUpdates(subscription, updates)
		return err
	}); err != nil {
		return err
	}
	if !needed {
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	blocked, err := MeshBlockedEmails(c.DB, time.Now().Unix())
	if err != nil {
		return err
	}
	if err := c.Enforcer.apply(ctx, blocked); err != nil {
		return err
	}
	if err := c.Drain(ctx, emails); err != nil {
		return err
	}
	if err := c.Flush(ctx); err != nil {
		return err
	}
	if err := c.transaction(func(tx *gorm.DB) error {
		store := quotaescrow.NewStore(tx)
		for _, email := range emails {
			var local model.LocalUsage
			if err := tx.First(&local, "email = ?", email).Error; err != nil {
				return err
			}
			if err := store.ObserveMeter(subscription, c.Owner, local.Source, c.Key, local.Billed); err != nil {
				return err
			}
		}
		policy, kind, err := store.CommitSharedUpdates(subscription, c.Owner, c.Key)
		if err != nil {
			return err
		}
		return commitMeshClientPolicy(tx, policy, kind, emails)
	}); err != nil {
		return err
	}
	// Only the supervised enforcement cycle reopens, after its own checkpoint.
	return check()
}

// ResumeSharedUpdates recovers a crash between barrier persistence and final
// commit. It is bounded and does not require any network peer to be available.
func (c *MeshControl) ResumeSharedUpdates(ctx context.Context) error {
	var records []quotaescrow.Record
	if err := c.DB.Where("pending_updates_json <> ? AND pending_updates_json <> ?", "[]", "").Order("subscription").Limit(8).Find(&records).Error; err != nil {
		return err
	}
	var failures []error
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, errors.Join(failures...))
		}
		var updates []quotaescrow.PolicyUpdate
		if err := json.Unmarshal([]byte(r.PendingUpdatesJSON), &updates); err != nil {
			return err
		}
		if err := c.ApplySharedUpdates(ctx, r.Subscription, updates); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (c *MeshControl) SharedUpdatesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var request quotaescrow.PolicyUpdateRequest
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || len(request.Updates) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := c.ApplySharedUpdates(ctx, request.Subscription, request.Updates); err != nil {
			http.Error(w, "policy not committed; pending barrier retained", http.StatusConflict)
			return
		}
		var record quotaescrow.Record
		if c.DB.First(&record, "subscription = ?", request.Subscription).Error != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var p quotaescrow.Policy
		if json.Unmarshal([]byte(record.PolicyJSON), &p) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		receipt, err := quotaescrow.SignPolicyReceipt(p, c.Owner, c.Key)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}
