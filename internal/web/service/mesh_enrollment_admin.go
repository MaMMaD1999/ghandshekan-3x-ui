package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Only configured enrollment managers hold this key. Existing subscriptions
// still require the majority's policy log; this service cannot renew/reset
// them or bypass the pinned membership registry.
type MeshEnrollmentAdministrator struct {
	manager *MeshAdministrator
	builder quotaescrow.PlanBuilder
	mu      sync.Mutex
}

var activeMeshEnrollment atomic.Pointer[MeshEnrollmentAdministrator]

type MeshEnrollmentInput struct {
	Subscription string   `json:"subscription"`
	Emails       []string `json:"emails"`
	Limit        int64    `json:"limit"`
	ExpiresAt    int64    `json:"expiresAt"`
	Disabled     bool     `json:"disabled"`
	Unlimited    bool     `json:"unlimited"`
}

func OpenMeshEnrollmentAdministrator(c *MeshConfig, local *MeshControl, transport quotaescrow.ControlClient, quorum *MeshQuorum) (*MeshEnrollmentAdministrator, error) {
	if c.EnrollmentAuthorityFile == "" {
		return nil, nil
	}
	if quorum == nil {
		return nil, errors.New("enrollment has no majority controller")
	}
	private := *c
	private.AuthorityFile, private.JournalFile = c.EnrollmentAuthorityFile, c.EnrollmentJournalFile
	a, err := OpenMeshAdministrator(&private, local, transport)
	if err != nil {
		return nil, err
	}
	coordinator := a.Coordinator
	coordinator.ControlEpoch, coordinator.ControlKeys = c.ControlEpoch, c.PeerKeys
	coordinator.RegisterPolicy = func(ctx context.Context, p quotaescrow.Policy) error {
		r, err := meshconsensus.SignRegistration(p, coordinator.Authority)
		if err != nil {
			return err
		}
		_, err = quorum.Node.Execute(ctx, meshconsensus.Command{ID: "enroll-" + quotaescrow.PolicyHash(p), Registration: &r})
		return err
	}
	return &MeshEnrollmentAdministrator{manager: a, builder: quotaescrow.PlanBuilder{Authority: coordinator.Authority, Keys: c.PeerKeys, Inspect: transport.Inspect}}, nil
}

func (a *MeshEnrollmentAdministrator) Close() {
	if a == nil {
		return
	}
	activeMeshEnrollment.CompareAndSwap(a, nil)
	a.manager.Close()
}

func (a *MeshEnrollmentAdministrator) Run(ctx context.Context) {
	a.manager.Run(ctx)
}

func (a *MeshEnrollmentAdministrator) Queue(ctx context.Context, input MeshEnrollmentInput, key string) (MeshOperationResult, error) {
	var out MeshOperationResult
	input.Emails = trimmedUniqueEmails(input.Emails)
	slices.Sort(input.Emails)
	if key == "" || input.Subscription == "" || len(input.Subscription) > 512 || len(input.Emails) == 0 || len(input.Emails) > 2000 || input.Limit < 0 || input.ExpiresAt < 0 || input.ExpiresAt > math.MaxInt64/1000 || (input.Unlimited && input.Limit != 0) {
		return out, errors.New("invalid initial subscription enrollment")
	}
	id, err := meshOperationID(input.Subscription, "enroll", key)
	if err != nil {
		return out, err
	}
	// Deterministic IDs and a separate durable journal make a lost HTTP reply
	// resumable. Never re-plan a prepared subscription with a new baseline.
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.manager.Coordinator
	var job quotaescrow.ControlJob
	err = c.DB.First(&job, "id = ?", id).Error
	target := quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: input.Limit, ExpiresAt: input.ExpiresAt, Disabled: input.Disabled, Unlimited: input.Unlimited}
	roots := make([]quotaescrow.LegacyRoot, len(input.Emails))
	for i, email := range input.Emails {
		roots[i] = quotaescrow.LegacyRoot{Owner: c.Owner, Alias: email}
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var existing int64
		if err := c.DB.Model(&quotaescrow.ControlJob{}).Where("subscription = ?", input.Subscription).Count(&existing).Error; err != nil {
			return out, err
		}
		if existing != 0 {
			return out, errors.New("subscription enrollment already exists; retry its original request")
		}
		plan, weights, err := a.builder.Enrollment(ctx, input.Subscription, roots)
		if err != nil {
			return out, err
		}
		plan.ID, target.Weights = id, weights
		keys := map[string][]byte{}
		for owner := range plan.Claims {
			keys[owner] = a.builder.Keys[owner]
		}
		if err := c.Create(plan, nil, target, keys); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else {
		var saved quotaescrow.ControlTarget
		var plan quotaescrow.ControlPlan
		if json.Unmarshal([]byte(job.TargetJSON), &saved) != nil || json.Unmarshal([]byte(job.PlanJSON), &plan) != nil {
			return out, errors.New("invalid saved enrollment")
		}
		target.Weights = saved.Weights
		if plan.Kind != "enroll" || plan.Subscription != input.Subscription || !reflect.DeepEqual(plan.AccountingRoots, roots) || !reflect.DeepEqual(target, saved) {
			return out, errors.New("enrollment request ID reused with different inputs")
		}
	}
	out = MeshOperationResult{Operation: id, Pending: true}
	_, complete, err := c.Resume(ctx, id)
	out.Pending = !complete
	select {
	case a.manager.wake <- struct{}{}:
	default:
	}
	return out, err
}

// A native client gets a stable identity scoped to its managing panel. It is
// never inferred from a display name shared with a different panel.
func NativeMeshSubscription(owner, email, credential string) string {
	h := sha256.Sum256([]byte(owner + "\x00" + email + "\x00" + credential))
	return "native-" + hex.EncodeToString(h[:])
}

func QueueMeshEnrollment(ctx context.Context, input MeshEnrollmentInput, key string) (MeshOperationResult, error) {
	a := activeMeshEnrollment.Load()
	if a == nil {
		return MeshOperationResult{}, errors.New("initial enrollment manager is not configured on this panel")
	}
	return a.Queue(ctx, input, key)
}

func MeshCapabilities() map[string]any {
	runtime := activeMeshAdministrator.Load() != nil && meshCanAdmit()
	return map[string]any{"protocolVersion": 1, "runtimeReady": runtime, "enrollmentReady": runtime && activeMeshEnrollment.Load() != nil, "usageMode": "shared", "independentCutoff": runtime}
}
