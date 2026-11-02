package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ActivateMeshMeters is the storage half of enrollment. The caller must first
// authenticate the policy, pause and drain runtime admission, and validate ALL
// aliases/protocols against its authoritative subscription. This is deliberately
// not exposed as an unauthenticated node API. No names/ports infer membership.
// Existing local counters are baselines, never fresh billable consumption.
func ActivateMeshMeters(db *gorm.DB, p quotaescrow.Policy, owner string, emails []string) error {
	if len(emails) == 0 || len(p.Keys[owner]) != ed25519.PublicKeySize {
		return errors.New("missing local membership")
	}
	seen := map[string]bool{}
	for _, email := range emails {
		if email == "" || seen[email] {
			return errors.New("invalid or duplicate alias")
		}
		seen[email] = true
	}
	return db.Transaction(func(tx *gorm.DB) error {
		meters := make([]quotaescrow.Meter, 0, len(emails))
		bindings := make([]model.MeshBinding, 0, len(emails))
		for _, email := range emails {
			// Create only if absent; an existing monotonic source must never be reset.
			initial := model.LocalUsage{Email: email, Source: rand.Text()}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&initial).Error; err != nil {
				return err
			}
			var local model.LocalUsage
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&local, "email = ?", email).Error; err != nil {
				return err
			}
			if local.Source == "" || local.Billed < 0 {
				return errors.New("invalid durable local source")
			}
			meters = append(meters, quotaescrow.Meter{Subscription: p.Subscription, Owner: owner, Source: local.Source, Epoch: p.Epoch, Watermark: local.Billed})
			bindings = append(bindings, model.MeshBinding{Email: email, Subscription: p.Subscription, Owner: owner})
		}
		if err := quotaescrow.NewStore(tx).Activate(p, meters); err != nil {
			return err
		}
		// An alias cannot silently migrate to another policy or owner. A uniqueness
		// failure rolls back the policy, baselines and all earlier aliases together.
		return tx.Create(&bindings).Error
	})
}

// SettleMeshMeters processes each subscription atomically, aggregating all its
// local aliases. Missing meters/keys and regressed counters are explicit errors;
// callers must hold admission closed for those subscriptions until reconciled.
// A failed subscription does not prevent unrelated subscriptions settling.
// It never reads global/mirrored client_traffics or applies coefficients again.
func SettleMeshMeters(db *gorm.DB, keyForOwner func(string) (ed25519.PrivateKey, error)) (map[string]error, error) {
	if keyForOwner == nil {
		return nil, errors.New("missing signing key resolver")
	}
	var bindings []model.MeshBinding
	if err := db.Order("subscription, email").Find(&bindings).Error; err != nil {
		return nil, err
	}
	groups := map[string][]model.MeshBinding{}
	for _, b := range bindings {
		groups[b.Subscription] = append(groups[b.Subscription], b)
	}
	failures := map[string]error{}
	for subscription, aliases := range groups {
		err := db.Transaction(func(tx *gorm.DB) error {
			store := quotaescrow.NewStore(tx)
			for _, b := range aliases {
				key, err := keyForOwner(b.Owner)
				if err != nil {
					return fmt.Errorf("local signer: %w", err)
				}
				var local model.LocalUsage
				if err := tx.First(&local, "email = ?", b.Email).Error; err != nil {
					return fmt.Errorf("local counter: %w", err)
				}
				if err := store.ObserveMeter(subscription, b.Owner, local.Source, key, local.Billed); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			failures[subscription] = err
		}
	}
	return failures, nil
}
