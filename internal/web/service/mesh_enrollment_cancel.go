package service

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Execute has already verified the authority signature and serialized against
// prepare/commit. This terminal receipt survives lost replies and DB checkpoints.
// It never deletes a meter, modifies traffic or undoes committed enrollment.
func (c *MeshControl) cancelEnrollment(plan quotaescrow.ControlPlan) (quotaescrow.ControlReceipt, error) {
	var out quotaescrow.ControlReceipt
	if plan.Kind != "enroll" {
		return out, errors.New("cannot cancel a subscription lifecycle")
	}
	err := c.transaction(func(tx *gorm.DB) error {
		var state model.MeshControlState
		err := tx.First(&state, "id = ?", plan.ID).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && (state.Stage == 2 || state.PlanHash != quotaescrow.ControlPlanHash(plan)) {
			return errors.New("committed or different enrollment cannot be canceled")
		}
		if state.CancelReceiptJSON != "" {
			if err := json.Unmarshal([]byte(state.CancelReceiptJSON), &out); err != nil {
				return err
			}
			return quotaescrow.VerifyEnrollmentCancellation(out, plan, c.Key.Public().(ed25519.PublicKey))
		}
		var count int64
		if err := tx.Model(&quotaescrow.Record{}).Where("subscription = ?", plan.Subscription).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return errors.New("enrollment already has an accounting policy")
		}
		if state.ID == "" {
			body, _ := json.Marshal(plan)
			placeholder, _ := json.Marshal(quotaescrow.ControlReceipt{Owner: c.Owner})
			state = model.MeshControlState{ID: plan.ID, Subscription: plan.Subscription, PlanHash: quotaescrow.ControlPlanHash(plan), PlanJSON: string(body), ReceiptJSON: string(placeholder)}
		}
		out, err = quotaescrow.SignControlReceipt(quotaescrow.ControlReceipt{Canceled: true, PlanHash: state.PlanHash, Owner: c.Owner}, c.Key)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(out)
		state.CancelReceiptJSON = string(body)
		return tx.Save(&state).Error
	})
	if err == nil {
		err = c.Checkpoint()
	}
	return out, err
}

func meshCanceledEnrollmentAliases(db *gorm.DB, keyForOwner func(string) (ed25519.PrivateKey, error)) (map[string]bool, error) {
	out := map[string]bool{}
	if !db.Migrator().HasTable(&model.MeshControlState{}) {
		return out, nil
	}
	var rows []model.MeshControlState
	if err := db.Where("cancel_receipt_json <> ?", "").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, state := range rows {
		var receipt quotaescrow.ControlReceipt
		var plan quotaescrow.ControlPlan
		if state.Stage >= 2 || json.Unmarshal([]byte(state.PlanJSON), &plan) != nil || json.Unmarshal([]byte(state.CancelReceiptJSON), &receipt) != nil || !receipt.Canceled || receipt.PlanHash != quotaescrow.ControlPlanHash(plan) || len(plan.Claims[receipt.Owner]) == 0 {
			return nil, errors.New("invalid canceled enrollment barrier")
		}
		if keyForOwner == nil {
			return nil, errors.New("cancellation signer unavailable")
		}
		key, err := keyForOwner(receipt.Owner)
		if err != nil || len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("cancellation owner is not local")
		}
		if err := quotaescrow.VerifyEnrollmentCancellation(receipt, plan, key.Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
		for _, claim := range plan.Claims[receipt.Owner] {
			out[claim.Email] = true
		}
	}
	return out, nil
}
