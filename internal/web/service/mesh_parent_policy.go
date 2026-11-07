package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

// Explicit parent scope avoids selecting a device alias that was subsequently
// revoked. CAS protects a stale application sale from overwriting a renewal
// accepted by the surviving majority while its managing panel was offline.
type MeshParentPolicyInput struct {
	Subscription string `json:"subscription"`
	ControlEpoch string `json:"controlEpoch"`
	Epoch        string `json:"epoch"`
	ExpectedHash string `json:"expectedHash"`
	Kind         string `json:"kind"`
	Limit        int64  `json:"limit"`
	ExpiresAt    int64  `json:"expiresAt"`
	Disabled     *bool  `json:"disabled"`
	Unlimited    *bool  `json:"unlimited"`
}

type MeshParentPolicyResult struct {
	Operation          string `json:"operation"`
	MajorityCommitted  bool   `json:"majorityCommitted"`
	ApplicationPending bool   `json:"applicationPending"`
	PolicyVersion      uint64 `json:"policyVersion"`
	PolicyHash         string `json:"policyHash"`
	ResetGeneration    uint64 `json:"resetGeneration"`
}

func parentPolicyCommand(input MeshParentPolicyInput, key string, local quotaescrow.Policy) (meshconsensus.Command, error) {
	var empty meshconsensus.Command
	h, err := hex.DecodeString(input.ExpectedHash)
	if key == "" || err != nil || len(h) != sha256.Size || input.ExpectedHash != hex.EncodeToString(h) ||
		(input.Kind != "renew" && input.Kind != "reset") || input.Limit < 0 || input.ExpiresAt < 0 || input.ExpiresAt > math.MaxInt64/1000 ||
		input.Disabled == nil || input.Unlimited == nil || (*input.Unlimited && input.Limit != 0) {
		return empty, errors.New("invalid explicit parent lifecycle request")
	}
	if input.Subscription != local.Subscription || input.ControlEpoch == "" || input.ControlEpoch != local.ControlEpoch ||
		input.Epoch == "" || input.Epoch != local.Epoch || local.Mode != "shared" || local.Aliases == nil {
		return empty, errors.New("parent lifecycle scope changed")
	}
	id, err := meshOperationID(input.Subscription, "parent-"+input.Kind, key)
	if err != nil {
		return empty, err
	}
	// Do not compare ExpectedHash against the local replica here: consensus
	// first recovers an accepted retry, otherwise compares the committed head.
	return meshconsensus.Command{ID: id, Subscription: input.Subscription, Kind: input.Kind, ExpectedHash: input.ExpectedHash,
		Patch: &meshconsensus.PolicyPatch{Limit: &input.Limit, ExpiresAt: &input.ExpiresAt, Disabled: input.Disabled, Unlimited: input.Unlimited}}, nil
}

func QueueMeshParentPolicy(ctx context.Context, input MeshParentPolicyInput, key string) (MeshParentPolicyResult, error) {
	var out MeshParentPolicyResult
	a := activeMeshAdministrator.Load()
	if a == nil || a.Quorum == nil {
		return out, errors.New("majority parent lifecycle is unavailable")
	}
	q := a.Quorum
	l, err := quotaescrow.NewStore(q.Local.DB).Load(input.Subscription)
	if err != nil {
		return out, err
	}
	command, err := parentPolicyCommand(input, key, l.Policy())
	if err != nil {
		return out, err
	}
	result, err := q.Node.Execute(ctx, command)
	if err != nil {
		return out, err
	}
	if result.Error != "" {
		return out, errors.New(result.Error)
	}
	u := result.Update
	if u == nil || u.ID != command.ID || u.Next.Subscription != input.Subscription || u.Kind != input.Kind {
		return out, errors.New("missing majority parent lifecycle receipt")
	}
	out = MeshParentPolicyResult{Operation: command.ID, MajorityCommitted: true, ApplicationPending: true,
		PolicyVersion: u.Next.Version, PolicyHash: quotaescrow.PolicyHash(u.Next), ResetGeneration: u.Next.ResetGeneration}
	// Local application is retried by the supervisor. Its failure after the
	// majority decision must not make the application issue a second reset.
	_ = q.synchronize(ctx, input.Subscription, u.Next.Version)
	return out, nil
}
