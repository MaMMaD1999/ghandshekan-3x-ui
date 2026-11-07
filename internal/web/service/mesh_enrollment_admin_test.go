package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func enrollmentAdminFixture(t *testing.T) (*MeshEnrollmentAdministrator, *MeshControl) {
	t.Helper()
	node, authority, _, _ := controlFixture(t, "manager")
	if err := node.DB.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		t.Fatal(err)
	}
	builder := quotaescrow.PlanBuilder{Authority: authority, Keys: map[string][]byte{node.Owner: node.Key.Public().(ed25519.PublicKey)}, Inspect: func(_ context.Context, owner string, request quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		if owner != node.Owner {
			return quotaescrow.Inventory{}, errors.New("unknown test member")
		}
		return node.Inspect(request)
	}}
	c := &quotaescrow.Coordinator{Owner: node.Owner, DB: node.DB, Authority: authority, CheckReady: builder.CheckReady, Call: func(ctx context.Context, owner string, request quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
		if owner != node.Owner {
			return quotaescrow.ControlReceipt{}, errors.New("unknown test member")
		}
		return node.Execute(ctx, request)
	}}
	return &MeshEnrollmentAdministrator{manager: &MeshAdministrator{Coordinator: c, Local: node, wake: make(chan struct{}, 1)}, builder: builder}, node
}

func TestMeshEnrollmentAdminRetriesLostPrepareAndCommitWithoutRebilling(t *testing.T) {
	for _, lostOperation := range []string{"prepare", "commit"} {
		t.Run(lostOperation, func(t *testing.T) {
			a, node := enrollmentAdminFixture(t)
			call := a.manager.Coordinator.Call
			lost := false
			a.manager.Coordinator.Call = func(ctx context.Context, owner string, request quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
				r, err := call(ctx, owner, request)
				if err == nil && request.Command.Operation == lostOperation && !lost {
					lost = true
					return quotaescrow.ControlReceipt{}, errors.New("reply lost after durable write")
				}
				return r, err
			}
			input := MeshEnrollmentInput{Subscription: "finite-parent", Emails: []string{" phone ", "phone"}, Limit: 1000}
			first, err := a.Queue(context.Background(), input, "enrollment-one")
			if err == nil || !first.Pending || first.Operation == "" || !lost {
				t.Fatal("missing recoverable operation", first, err)
			}
			// A retry must not inspect again: our own prepare barrier (or the
			// committed enrollment) is no longer a pristine legacy subscription.
			a.builder.Inspect = func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
				t.Fatal("retry replanned the enrollment")
				return quotaescrow.Inventory{}, nil
			}
			if lostOperation == "commit" {
				if err := node.DB.Transaction(func(tx *gorm.DB) error { return recordMeshLocalUsage(tx, "phone", 17, 0) }); err != nil {
					t.Fatal(err)
				}
			}
			repeated, err := a.Queue(context.Background(), input, "enrollment-one")
			if err != nil || repeated.Pending || first.Operation != repeated.Operation {
				t.Fatal("resume failed", repeated, err)
			}
			failures, err := SettleMeshMeters(node.DB, func(string) (ed25519.PrivateKey, error) { return node.Key, nil })
			if err != nil || len(failures) != 0 {
				t.Fatal(failures, err)
			}
			ledger, err := quotaescrow.NewStore(node.DB).Load(input.Subscription)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(100)
			if lostOperation == "commit" {
				want += 17
			}
			if billed, err := ledger.Billed(); err != nil || billed != want {
				t.Fatal("enrollment lost or duplicated usage", billed, want, err)
			}
			if _, err := a.Queue(context.Background(), input, "different-key"); err == nil {
				t.Fatal("re-enrolled the same subscription")
			}
			input.Limit++
			if _, err := a.Queue(context.Background(), input, "enrollment-one"); err == nil {
				t.Fatal("changed immutable request accepted")
			}
		})
	}
}

func TestMeshEnrollmentAdminReadOnlyDiscoveryFailure(t *testing.T) {
	a, node := enrollmentAdminFixture(t)
	a.builder.Inspect = func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		return quotaescrow.Inventory{}, errors.New("member unreachable")
	}
	if _, err := a.Queue(context.Background(), MeshEnrollmentInput{Subscription: "finite-parent", Emails: []string{"phone"}, Limit: 1000}, "one"); err == nil {
		t.Fatal("missing member accepted")
	}
	for _, table := range []any{&model.MeshControlState{}, &model.MeshBinding{}, &quotaescrow.ControlJob{}} {
		var count int64
		if err := node.DB.Model(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("read-only failure changed serving client", count, err)
		}
	}
}

func TestMeshEnrollmentAdminRejectsInvalidPolicyBeforeInspection(t *testing.T) {
	a, _ := enrollmentAdminFixture(t)
	a.builder.Inspect = func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		t.Fatal("invalid input reached discovery")
		return quotaescrow.Inventory{}, nil
	}
	for _, input := range []MeshEnrollmentInput{
		{Subscription: "s", Emails: []string{"phone"}, Limit: -1},
		{Subscription: "s", Emails: []string{"phone"}, Limit: 1, Unlimited: true},
		{Subscription: "s", Emails: []string{"phone"}, ExpiresAt: math.MaxInt64},
		{Subscription: "s", Emails: []string{" "}},
		{Emails: []string{"phone"}},
	} {
		if _, err := a.Queue(context.Background(), input, "one"); err == nil {
			t.Fatal("invalid policy accepted", input)
		}
	}
	if _, err := a.Queue(context.Background(), MeshEnrollmentInput{Subscription: "s", Emails: []string{"phone"}}, ""); err == nil {
		t.Fatal("missing retry identity accepted")
	}
}

func TestMeshEnrollmentConfigRequiresSeparateMajorityJournal(t *testing.T) {
	_, c := meshRuntimeFixture(t, "local")
	c.PeerKeys = map[string][]byte{c.Owner: ed25519.PrivateKey(c.PrivateKey).Public().(ed25519.PublicKey)}
	c.EnrollmentAuthorityFile = filepath.Join(t.TempDir(), "authority.json")
	if err := c.validate(); err == nil {
		t.Fatal("unpaired enrollment key accepted")
	}
	c.EnrollmentJournalFile = filepath.Join(t.TempDir(), "enrollment.db")
	if err := c.validate(); err == nil {
		t.Fatal("enrollment without majority accepted")
	}
	c.ControlEpoch = "cluster-one"
	c.JournalFile = c.EnrollmentJournalFile
	if err := c.validate(); err == nil {
		t.Fatal("shared lifecycle journal accepted")
	}
}
