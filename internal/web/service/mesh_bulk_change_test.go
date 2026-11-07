package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
)

func TestMeshBulkChangeGroupsDeviceAliasesOnce(t *testing.T) {
	db, _, first := legacyGuardFixture(t)
	if err := db.Create(&model.MeshBinding{Email: "second-device", Subscription: "sub", Owner: "local"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.MeshBinding{Email: "another-user", Subscription: "sub-b", Owner: "local"}).Error; err != nil {
		t.Fatal(err)
	}
	groups, ordinary, err := meshBatchGroups(db, []string{first.Email, "second-device", first.Email, "another-user", "ordinary"})
	if err != nil || len(groups) != 2 || len(groups["sub"]) != 2 || !reflect.DeepEqual(ordinary, []string{"ordinary"}) {
		t.Fatal(groups, ordinary, err)
	}
	var calls []string
	patch := &meshconsensus.PolicyPatch{AddBytes: 100}
	queue := func(_ context.Context, sub, kind, key string, got *meshconsensus.PolicyPatch) (MeshOperationResult, error) {
		if kind != "renew" || key != "repeat-id" || got != patch {
			t.Fatal("changed durable request")
		}
		calls = append(calls, sub)
		return MeshOperationResult{}, nil
	}
	handled, count, rest, err := applyMeshBatch(context.Background(), groups, ordinary, "repeat-id", patch, queue)
	if err != nil || !handled || count != 3 || !reflect.DeepEqual(rest, ordinary) || !reflect.DeepEqual(calls, []string{"sub", "sub-b"}) {
		t.Fatal(handled, count, rest, calls, err)
	}
	// A failed majority request never hands ordinary clients to the legacy
	// mutation path as though the mesh portion had succeeded.
	_, count, _, err = applyMeshBatch(context.Background(), groups, ordinary, "repeat-id", patch, func(context.Context, string, string, string, *meshconsensus.PolicyPatch) (MeshOperationResult, error) {
		return MeshOperationResult{}, errors.New("no majority")
	})
	if count != 0 || err == nil {
		t.Fatal("partial failure lost", count, err)
	}
}
