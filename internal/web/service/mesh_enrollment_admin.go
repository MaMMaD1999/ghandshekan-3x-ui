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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Only configured enrollment managers hold this key. Existing subscriptions
// still require the majority's policy log; this service cannot renew/reset
// them or bypass the pinned membership registry.
type MeshEnrollmentAdministrator struct {
	manager          *MeshAdministrator
	builder          quotaescrow.PlanBuilder
	mu               sync.Mutex
	aliasMu          sync.Mutex
	aliasPolicy      func(string) (quotaescrow.Policy, error)
	aliasExecute     func(context.Context, meshconsensus.Command) (meshconsensus.Result, error)
	aliasSync        func(context.Context, string, uint64) error
	nativeEnabled    bool
	nativeExclude    []string
	nativeConfigPath string
}

var activeMeshEnrollment atomic.Pointer[MeshEnrollmentAdministrator]

type MeshEnrollmentInput struct {
	Subscription string                   `json:"subscription"`
	Emails       []string                 `json:"emails"`
	Roots        []quotaescrow.LegacyRoot `json:"roots,omitempty"`
	Limit        int64                    `json:"limit"`
	ExpiresAt    int64                    `json:"expiresAt"`
	Disabled     bool                     `json:"disabled"`
	Unlimited    bool                     `json:"unlimited"`
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
	if err := coordinator.DB.AutoMigrate(&meshAliasJob{}); err != nil {
		a.Close()
		return nil, err
	}
	return &MeshEnrollmentAdministrator{manager: a, builder: quotaescrow.PlanBuilder{Authority: coordinator.Authority, Keys: c.PeerKeys, Inspect: transport.Inspect}, aliasPolicy: quorum.Node.FSM.Policy, aliasExecute: quorum.Node.Execute, aliasSync: quorum.synchronize, nativeEnabled: c.NativeEnrollment, nativeExclude: slices.Clone(c.NativeEnrollmentExclude), nativeConfigPath: MeshConfigPath()}, nil
}

func (a *MeshEnrollmentAdministrator) Close() {
	if a == nil {
		return
	}
	activeMeshEnrollment.CompareAndSwap(a, nil)
	a.manager.Close()
}

func (a *MeshEnrollmentAdministrator) Run(ctx context.Context) {
	nativeDone := make(chan struct{})
	go func() {
		defer close(nativeDone)
		a.runNativeEnrollment(ctx)
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cursor := ""
		for ctx.Err() == nil {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			cursor = a.resumeAliasJobs(bounded, cursor)
			cancel()
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	a.manager.Run(ctx)
	<-done
	<-nativeDone
}

func (a *MeshEnrollmentAdministrator) Queue(ctx context.Context, input MeshEnrollmentInput, key string) (MeshOperationResult, error) {
	return a.queue(ctx, input, key, "")
}

func (a *MeshEnrollmentAdministrator) queue(ctx context.Context, input MeshEnrollmentInput, key, expectedInitialState string) (MeshOperationResult, error) {
	var out MeshOperationResult
	input.Emails = trimmedUniqueEmails(input.Emails)
	slices.Sort(input.Emails)
	if key == "" || input.Subscription == "" || len(input.Subscription) > 512 || len(input.Emails)+len(input.Roots) == 0 || len(input.Emails)+len(input.Roots) > 2000 || (len(input.Emails) > 0 && len(input.Roots) > 0) || input.Limit < 0 || input.ExpiresAt < 0 || input.ExpiresAt > math.MaxInt64/1000 || (input.Unlimited && input.Limit != 0) {
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
	roots := slices.Clone(input.Roots)
	localEmails := slices.Clone(input.Emails)
	if len(roots) == 0 {
		for _, email := range input.Emails {
			roots = append(roots, quotaescrow.LegacyRoot{Owner: c.Owner, Alias: email})
		}
	} else {
		for _, root := range roots {
			if root.Owner == "" || root.Alias == "" || len(root.Alias) > 512 || strings.ContainsAny(root.Alias, "\x00\r\n") || len(a.builder.Keys[root.Owner]) != 32 {
				return out, errors.New("explicit enrollment root is not a registered member alias")
			}
			if root.Owner == c.Owner {
				localEmails = append(localEmails, root.Alias)
			}
		}
		if len(localEmails) == 0 {
			return out, errors.New("enrollment manager must own a root of the requested parent")
		}
	}
	slices.SortFunc(roots, func(a, b quotaescrow.LegacyRoot) int {
		if v := strings.Compare(a.Owner, b.Owner); v != 0 {
			return v
		}
		return strings.Compare(a.Alias, b.Alias)
	})
	for i := 1; i < len(roots); i++ {
		if roots[i] == roots[i-1] {
			return out, errors.New("duplicate enrollment accounting root")
		}
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var existing int64
		if err := c.DB.Model(&quotaescrow.ControlJob{}).Where("subscription = ? AND (cancel_requested = ? OR complete = ?)", input.Subscription, false, false).Count(&existing).Error; err != nil {
			return out, err
		}
		if existing != 0 {
			return out, errors.New("subscription enrollment already exists; retry its original request")
		}
		plan, weights, err := a.builder.Enrollment(ctx, input.Subscription, roots)
		if err != nil {
			return out, err
		}
		if expectedInitialState != "" && (len(input.Emails) != 1 || plan.InitialStates[c.Owner][input.Emails[0]] != expectedInitialState) {
			return out, errors.New("native subscription changed during enrollment discovery; refresh and retry")
		}
		target.ResetSchedule, err = enrollmentResetSchedule(a.manager.Local.DB, localEmails)
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
		out.Scope = &MeshAccountScope{Subscription: plan.Subscription, ControlEpoch: c.ControlEpoch, Epoch: plan.NextEpoch}
	} else if err != nil {
		return out, err
	} else {
		var saved quotaescrow.ControlTarget
		var plan quotaescrow.ControlPlan
		if json.Unmarshal([]byte(job.TargetJSON), &saved) != nil || json.Unmarshal([]byte(job.PlanJSON), &plan) != nil {
			return out, errors.New("invalid saved enrollment")
		}
		target.Weights = saved.Weights
		target.ResetSchedule = saved.ResetSchedule
		if plan.Kind != "enroll" || plan.Subscription != input.Subscription || !reflect.DeepEqual(plan.AccountingRoots, roots) || !reflect.DeepEqual(target, saved) {
			return out, errors.New("enrollment request ID reused with different inputs")
		}
		out.Scope = &MeshAccountScope{Subscription: plan.Subscription, ControlEpoch: c.ControlEpoch, Epoch: plan.NextEpoch}
	}
	out.Operation, out.Pending = id, true
	_, complete, err := c.Resume(ctx, id)
	out.Pending = !complete
	if complete && err == nil {
		if err = c.DB.First(&job, "id = ?", id).Error; err == nil {
			out.Frozen, err = enrollmentFrozenRoots(job)
		}
	}
	select {
	case a.manager.wake <- struct{}{}:
	default:
	}
	return out, err
}

func enrollmentFrozenRoots(job quotaescrow.ControlJob) ([]MeshFrozenRoot, error) {
	var plan quotaescrow.ControlPlan
	var receipts map[string]quotaescrow.ControlReceipt
	if !job.Complete || json.Unmarshal([]byte(job.PlanJSON), &plan) != nil || json.Unmarshal([]byte(job.ReceiptsJSON), &receipts) != nil {
		return nil, errors.New("completed enrollment receipt is unavailable")
	}
	list := make([]quotaescrow.ControlReceipt, 0, len(receipts))
	snapshots := make([]quotaescrow.LegacySnapshot, 0, len(receipts))
	for _, receipt := range receipts {
		list = append(list, receipt)
		if receipt.Historical != nil {
			snapshots = append(snapshots, *receipt.Historical)
		}
	}
	if _, err := quotaescrow.PreparedHistoricalUsage(plan, list); err != nil {
		return nil, err
	}
	counters, err := quotaescrow.FrozenHistoricalCounters(plan.AccountingRoots, snapshots)
	if err != nil {
		return nil, err
	}
	result := make([]MeshFrozenRoot, 0, len(plan.AccountingRoots))
	for _, root := range plan.AccountingRoots {
		v := counters[root]
		result = append(result, MeshFrozenRoot{Owner: root.Owner, Email: root.Alias, Up: v.Up, Down: v.Down})
	}
	return result, nil
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
	administrator := activeMeshAdministrator.Load()
	runtime := administrator != nil && administrator.Quorum != nil && meshCanAdmit()
	caps := map[string]any{"protocolVersion": 1, "runtimeReady": runtime, "enrollmentReady": runtime && activeMeshEnrollment.Load() != nil, "usageMode": "shared", "independentCutoff": runtime}
	if runtime {
		caps["parentAccountingVersion"] = 1
		caps["parentLifecycleVersion"] = 1
		if administrator.Local != nil && administrator.Quorum.Wire != nil {
			caps["owner"] = administrator.Local.Owner
			caps["controlEpoch"] = administrator.Quorum.Wire.Epoch
			caps["enrollmentVersion"] = 2
		}
	}
	return caps
}
