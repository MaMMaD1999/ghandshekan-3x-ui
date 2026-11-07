package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshEnrollmentCancellationReleasesOnlyUncommittedBarrier(t *testing.T) {
	c, authority, plan, checkpoint := controlFixture(t)
	prepared, err := controlRequest(t, c, authority, plan, "prepare", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := model.LocalUsage{}
	if err := c.DB.First(&before, "email = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	canceled, err := controlRequest(t, c, authority, plan, "cancel-enrollment", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := quotaescrow.VerifyEnrollmentCancellation(canceled, plan, c.Key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := quotaescrow.VerifyControlReceipt(canceled, plan, c.Key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("cancellation could be used to commit an accounting policy")
	}
	retry, err := controlRequest(t, c, authority, plan, "cancel-enrollment", nil, nil)
	if err != nil || !reflect.DeepEqual(retry, canceled) {
		t.Fatal("lost cancellation reply was not stable", err)
	}
	if _, err := controlRequest(t, c, authority, plan, "prepare", nil, nil); !errors.Is(err, quotaescrow.ErrEnrollmentCanceled) {
		t.Fatal("old prepare reopened cancellation", err)
	}
	policy := quotaescrow.Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: 1000, AlreadyBilled: 100, Grants: map[string]int64{c.Owner: 900}, Keys: map[string][]byte{c.Owner: c.Key.Public().(ed25519.PublicKey)}}
	if _, err := controlRequest(t, c, authority, plan, "commit", &policy, []quotaescrow.ControlReceipt{prepared}); err == nil {
		t.Fatal("delayed commit undid cancellation")
	}
	var after model.LocalUsage
	if err := c.DB.First(&after, "email = ?", "phone").Error; err != nil || after != before {
		t.Fatal("cancellation changed usage", err)
	}
	var blocked []string
	c.Enforcer.Checkpoint = c.Checkpoint
	c.Enforcer.KeyForOwner = func(string) (ed25519.PrivateKey, error) { return c.Key, nil }
	c.Enforcer.known = map[string]bool{"phone": true}
	c.Enforcer.Fence = func(_ context.Context, emails []string) error { blocked = emails; return nil }
	if err := c.Enforcer.Reconcile(context.Background(), 0); err != nil || len(blocked) != 0 {
		t.Fatal("canceled legacy client stayed fenced", blocked, err)
	}
	if err := c.DB.Model(&model.MeshControlState{}).Where("id = ?", plan.ID).Update("cancel_receipt_json", "").Error; err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Advance(c.DB); err == nil {
		t.Fatal("restored database removed cancellation")
	}
}

func TestNativeEnrollmentPreflightsLegacyResetBeforeFencingAnyPeer(t *testing.T) {
	a, node := enrollmentAdminFixture(t)
	if err := node.DB.Create(&model.NodePendingReset{NodeId: 9, Email: "phone", QueuedAt: 123}).Error; err != nil {
		t.Fatal(err)
	}
	a.builder.Inspect = func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		t.Fatal("prepared/discovered peers before resolving legacy reset")
		return quotaescrow.Inventory{}, nil
	}
	if _, err := a.QueueNative(context.Background(), "phone", "native-automatic-v1"); err == nil {
		t.Fatal("pending legacy reset accepted")
	}
	var count int64
	if err := node.DB.Model(&quotaescrow.ControlJob{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("created a partial enrollment", count, err)
	}
}

func TestCoordinatorCancellationSurvivesLostReplyAndCannotCancelCommittedPolicy(t *testing.T) {
	a, node := enrollmentAdminFixture(t)
	original := a.manager.Coordinator.Call
	stop := true
	a.manager.Coordinator.Call = func(ctx context.Context, owner string, request quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		receipt, err := original(ctx, owner, request)
		if err == nil && stop {
			stop = false
			return quotaescrow.ControlReceipt{}, errors.New("prepared reply lost")
		}
		return receipt, err
	}
	first, err := a.Queue(context.Background(), MeshEnrollmentInput{Subscription: "cancel-test", Emails: []string{"phone"}, Limit: 1000}, "first")
	if err == nil || first.Operation == "" {
		t.Fatal("expected prepared interruption", err)
	}
	lost := true
	a.manager.Coordinator.Call = func(ctx context.Context, owner string, request quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		receipt, err := original(ctx, owner, request)
		if err == nil && request.Command.Operation == "cancel-enrollment" && lost {
			lost = false
			return quotaescrow.ControlReceipt{}, errors.New("cancellation reply lost")
		}
		return receipt, err
	}
	if err := a.manager.Coordinator.CancelEnrollment(context.Background(), first.Operation); err == nil || errors.Is(err, quotaescrow.ErrEnrollmentCanceled) {
		t.Fatal("did not simulate lost reply", err)
	}
	if _, _, err := a.manager.Coordinator.Resume(context.Background(), first.Operation); !errors.Is(err, quotaescrow.ErrEnrollmentCanceled) {
		t.Fatal("could not recover terminal cancellation", err)
	}
	var job quotaescrow.ControlJob
	if err := node.DB.First(&job, "id = ?", first.Operation).Error; err != nil || !job.Complete || !job.CancelRequested {
		t.Fatal("cancellation not durable", err)
	}
	// A new, explicitly identified enrollment can now use unchanged history.
	second, err := a.Queue(context.Background(), MeshEnrollmentInput{Subscription: "cancel-test", Emails: []string{"phone"}, Limit: 1000}, "second")
	if err != nil || second.Pending {
		t.Fatal("could not re-enroll after cancellation", err)
	}
	if err := a.manager.Coordinator.CancelEnrollment(context.Background(), second.Operation); err == nil || errors.Is(err, quotaescrow.ErrEnrollmentCanceled) {
		t.Fatal("canceled committed policy", err)
	}
	var saved model.MeshControlState
	if err := node.DB.First(&saved, "id = ?", first.Operation).Error; err != nil {
		t.Fatal(err)
	}
	var receipt quotaescrow.ControlReceipt
	if json.Unmarshal([]byte(saved.CancelReceiptJSON), &receipt) != nil || !receipt.Canceled {
		t.Fatal("lost cancellation audit")
	}
}
