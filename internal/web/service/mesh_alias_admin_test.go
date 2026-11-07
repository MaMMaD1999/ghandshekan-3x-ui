package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMeshAliasRequestSurvivesLostReplyAndRevocationCannotBeReversed(t *testing.T) {
	c, p, _ := membershipFixture(t)
	a, _ := enrollmentAdminFixture(t)
	// Use the private coordinator DB as the durable request journal, and the
	// independently scoped member DB for runtime state.
	a.manager.Local = c
	a.manager.Coordinator.Owner = c.Owner
	if err := a.manager.Coordinator.DB.AutoMigrate(&meshAliasJob{}); err != nil {
		t.Fatal(err)
	}
	// This fixture's initial policy is already trusted by the runtime. Register
	// a fresh authority for the standalone consensus fixture, preserving keys.
	pub, authority, _ := ed25519.GenerateKey(nil)
	p.Authority = pub
	f, err := meshconsensus.NewFSM(p.ControlEpoch, p.ControlKeys, pub)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := meshconsensus.SignRegistration(p, authority)
	apply := func(command meshconsensus.Command) (meshconsensus.Result, error) {
		b, _ := json.Marshal(command)
		result := f.Apply(&raft.Log{Data: b}).(meshconsensus.Result)
		if result.Error != "" {
			return result, errors.New(result.Error)
		}
		return result, nil
	}
	if _, err := apply(meshconsensus.Command{ID: "registration", Registration: &r}); err != nil {
		t.Fatal(err)
	}
	provisionMembershipAlias(t, c, "tablet", false)
	a.builder = quotaescrow.PlanBuilder{Authority: authority, Keys: p.Keys, Inspect: func(_ context.Context, owner string, signed quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		// Actual member inspector authenticates the request before reading data.
		previous := c.Authority
		c.Authority = pub
		defer func() { c.Authority = previous }()
		return c.Inspect(signed)
	}}
	a.aliasPolicy = f.Policy
	lost := false
	a.aliasExecute = func(_ context.Context, command meshconsensus.Command) (meshconsensus.Result, error) {
		result, err := apply(command)
		if err == nil && !lost {
			lost = true
			return meshconsensus.Result{}, errors.New("reply lost after majority commit")
		}
		return result, err
	}
	a.aliasSync = func(context.Context, string, uint64) error { return nil }
	input := MeshAliasInput{Subscription: p.Subscription, Email: "tablet"}
	first, err := a.QueueAlias(context.Background(), input, "add-one")
	if err == nil || first.Operation == "" || !lost {
		t.Fatal("expected ambiguous committed reply", first, err)
	}
	a.builder.Inspect = func(context.Context, string, quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
		t.Fatal("retry or revocation re-inspected membership")
		return quotaescrow.Inventory{}, nil
	}
	retry, err := a.QueueAlias(context.Background(), input, "add-one")
	if err != nil || !retry.MajorityCommitted || first.Operation != retry.Operation || retry.PolicyVersion != 2 || retry.PolicyHash == "" || retry.ResetGeneration != p.ResetGeneration {
		t.Fatal(retry, err)
	}
	input.Revoke = true
	oldEnrollment := activeMeshEnrollment.Swap(nil)
	oldAdministrator := activeMeshAdministrator.Swap(&MeshAdministrator{Quorum: &MeshQuorum{revocations: a}})
	t.Cleanup(func() { activeMeshEnrollment.Store(oldEnrollment); activeMeshAdministrator.Store(oldAdministrator) })
	if _, err := QueueMeshAlias(context.Background(), input, "revoke-one"); err != nil {
		t.Fatal(err)
	}
	before, _ := f.Policy(p.Subscription)
	input.Revoke = false
	if replay, err := a.QueueAlias(context.Background(), input, "add-one"); err != nil || replay != retry {
		t.Fatal("original membership receipt changed after revocation", replay, err)
	}
	after, _ := f.Policy(p.Subscription)
	if quotaescrow.PolicyHash(before) != quotaescrow.PolicyHash(after) || !after.Aliases["a"]["tablet"].Revoked {
		t.Fatal("late attach retry resurrected a revoked device")
	}
	input.Email = "another-device"
	if _, err := a.QueueAlias(context.Background(), input, "add-one"); err == nil {
		t.Fatal("request identity reused for another device")
	}
}
