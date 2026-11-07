package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"time"

	"gorm.io/gorm"
)

// ControlTarget is an administrator's intended subscription limit/deadline.
// Weights allocate spending RIGHTS only; they never multiply billed traffic.
type ControlTarget struct {
	Mode      string           `json:"mode,omitempty"`
	Limit     int64            `json:"limit"`
	ExpiresAt int64            `json:"expiresAt"`
	Weights   map[string]int64 `json:"weights,omitempty"`
	Eventual  bool             `json:"eventual,omitempty"`
	Disabled  bool             `json:"disabled,omitempty"`
	Unlimited bool             `json:"unlimited,omitempty"`
}

type ControlJob struct {
	ID                string `gorm:"primaryKey"`
	Subscription      string `gorm:"index"`
	UpdatesJSON       string `gorm:"not null;default:'[]'"`
	Revision          uint64
	PlanJSON          string
	PriorJSON         string
	TargetJSON        string
	KeysJSON          string
	ReceiptsJSON      string
	PolicyJSON        string
	AcknowledgedJSON  string
	PreflightComplete bool
	Complete          bool
}

func (ControlJob) TableName() string { return "quota_escrow_control_jobs" }

// Coordinator persists progress before moving to the next phase. The host
// adapter provides authenticated private transport and an authoritative legacy
// usage cutover after EVERY member has drained. There is no guessed baseline.
type Coordinator struct {
	Owner          string
	DB             *gorm.DB
	Authority      ed25519.PrivateKey
	Call           func(context.Context, string, SignedControl) (ControlReceipt, error)
	InitialUsage   func(context.Context, ControlPlan, []ControlReceipt) (int64, error)
	CheckReady     func(context.Context, ControlPlan) error
	UpdatePolicy   func(context.Context, string, PolicyUpdateRequest) (PolicyReceipt, error)
	ControlEpoch   string
	ControlKeys    map[string][]byte
	RegisterPolicy func(context.Context, Policy) error
	mu             sync.Mutex
}

func (c *Coordinator) Create(plan ControlPlan, prior *Policy, target ControlTarget, keys map[string][]byte) error {
	if c.DB == nil || len(c.Authority) != ed25519.PrivateKeySize {
		return errors.New("coordinator unavailable")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if target.Limit < 0 || target.ExpiresAt < 0 || len(keys) != len(plan.Claims) || (target.Mode != "" && target.Mode != "shared") {
		return errors.New("invalid coordinator target")
	}
	if target.Eventual && target.Mode != "shared" {
		return errors.New("eventual lifecycle requires shared availability")
	}
	if !target.Eventual && (target.Disabled || target.Unlimited) {
		return errors.New("availability flags require versioned shared policy")
	}
	if target.Eventual && len(keys[c.Owner]) != ed25519.PublicKeySize {
		return errors.New("shared lifecycle requires a pinned managing owner")
	}
	if prior != nil && prior.Version > 0 && prior.Manager != c.Owner {
		return errors.New("only the managing panel may order lifecycle changes")
	}
	if prior != nil && prior.Version > 0 && (!target.Eventual || target.Mode != "shared") {
		return errors.New("versioned shared lifecycle cannot be downgraded")
	}
	seen := map[string]bool{}
	for owner := range plan.Claims {
		key := keys[owner]
		if len(key) != ed25519.PublicKeySize || c.Authority.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(key)) || seen[string(key)] {
			return errors.New("invalid member key")
		}
		seen[string(key)] = true
	}
	if plan.Kind == "enroll" {
		if prior != nil {
			return errors.New("initial enrollment has no old epoch")
		}
	} else {
		if prior == nil || prior.Subscription != plan.Subscription || prior.Epoch != plan.Epoch || !reflect.DeepEqual(prior.Keys, keys) {
			return errors.New("old policy scope or keys changed")
		}
		if _, err := New(*prior); err != nil {
			return err
		}
	}
	for owner, weight := range target.Weights {
		if len(keys[owner]) == 0 || weight < 0 || weight > 1000000 {
			return errors.New("invalid allocation weight")
		}
	}
	positive := false
	for owner := range keys {
		weight, explicit := target.Weights[owner]
		positive = positive || !explicit || weight > 0
	}
	if !positive && target.Limit > 0 {
		return errors.New("at least one traffic-serving member is required")
	}
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	job := ControlJob{ID: plan.ID, Subscription: plan.Subscription, Revision: 1, PlanJSON: encode(plan), PriorJSON: encode(prior), TargetJSON: encode(target), KeysJSON: encode(keys), ReceiptsJSON: "{}", AcknowledgedJSON: "{}", UpdatesJSON: "[]"}
	return c.DB.Transaction(func(tx *gorm.DB) error {
		var existing ControlJob
		err := tx.First(&existing, "id = ?", plan.ID).Error
		if err == nil {
			if existing.PlanJSON != job.PlanJSON || existing.PriorJSON != job.PriorJSON || existing.TargetJSON != job.TargetJSON || existing.KeysJSON != job.KeysJSON {
				return errors.New("coordinator operation ID already used")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if prior != nil && prior.Version > 0 {
			var candidates []ControlJob
			if err := tx.Where("subscription = ? AND policy_json <> ?", plan.Subscription, "").Find(&candidates).Error; err != nil {
				return err
			}
			var latest Policy
			var chain []PolicyUpdate
			for _, candidate := range candidates {
				var p Policy
				if json.Unmarshal([]byte(candidate.PolicyJSON), &p) != nil {
					return errors.New("invalid persisted shared policy")
				}
				if p.Version > latest.Version {
					latest = p
					chain, err = decodeUpdates(candidate.UpdatesJSON)
					if err != nil {
						return err
					}
				}
			}
			if !reflect.DeepEqual(latest, *prior) {
				return errors.New("subscription policy changed; refresh before updating")
			}
			u, err := SignPolicyChange(*prior, plan.ID, plan.Kind, target, c.Authority)
			if err != nil {
				return err
			}
			job.PolicyJSON = encode(u.Next)
			job.UpdatesJSON = encode(append(chain, u))
		}
		return tx.Create(&job).Error
	})
}

func (c *Coordinator) save(job *ControlJob, changes map[string]any) error {
	if job.Revision == ^uint64(0) {
		return errors.New("coordinator revision exhausted")
	}
	changes["revision"] = job.Revision + 1
	r := c.DB.Model(&ControlJob{}).Where("id = ? AND revision = ?", job.ID, job.Revision).Updates(changes)
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected != 1 {
		return ErrConflict
	}
	job.Revision++
	return nil
}

// Resume is safe after a network failure or process restart, including a lost
// response AFTER a member committed. The node's durable operation ID makes that
// retry a receipt lookup rather than another reset/renewal.
func (c *Coordinator) Resume(ctx context.Context, id string) (Policy, bool, error) {
	var empty Policy
	if c.DB == nil || c.Call == nil || len(c.Authority) != ed25519.PrivateKeySize {
		return empty, false, errors.New("coordinator unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var job ControlJob
	if err := c.DB.First(&job, "id = ?", id).Error; err != nil {
		return empty, false, err
	}
	var plan ControlPlan
	var prior *Policy
	var target ControlTarget
	var keys map[string][]byte
	var receipts map[string]ControlReceipt
	var acknowledged map[string]bool
	for _, field := range []struct {
		encoded string
		value   any
	}{{job.PlanJSON, &plan}, {job.PriorJSON, &prior}, {job.TargetJSON, &target}, {job.KeysJSON, &keys}, {job.ReceiptsJSON, &receipts}, {job.AcknowledgedJSON, &acknowledged}} {
		if err := json.Unmarshal([]byte(field.encoded), field.value); err != nil {
			return empty, false, err
		}
	}
	if receipts == nil || acknowledged == nil {
		return empty, false, errors.New("missing coordinator progress")
	}
	if err := plan.Validate(); err != nil {
		return empty, false, err
	}
	if plan.ID != id {
		return empty, false, errors.New("coordinator operation scope mismatch")
	}
	// Revalidate immutable inputs on resume too; a restored/corrupt job must
	// not bypass the validation performed on its original creation.
	if err := c.Create(plan, prior, target, keys); err != nil {
		return empty, false, err
	}
	if prior != nil && prior.Version > 0 {
		return c.resumeShared(ctx, &job, plan, *prior, target, acknowledged)
	}
	if len(receipts) == 0 && !job.PreflightComplete && c.CheckReady != nil {
		if err := c.CheckReady(ctx, plan); err != nil {
			return empty, false, err
		}
		// Persist BEFORE prepare: its reply may be lost after a member fenced.
		// Re-inspecting then would mistake our own durable barrier for a conflict.
		if err := c.save(&job, map[string]any{"preflight_complete": true}); err != nil {
			return empty, false, err
		}
	}
	owners := make([]string, 0, len(plan.Claims))
	for owner := range plan.Claims {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	request := func(owner, operation string, policy *Policy, prepared []ControlReceipt) (ControlReceipt, error) {
		if err := ctx.Err(); err != nil {
			return ControlReceipt{}, err
		}
		now := time.Now().Unix()
		signed, err := SignControl(ControlCommand{Plan: plan, Operation: operation, Policy: policy, Receipts: prepared, IssuedAt: now - 1, ValidUntil: now + 120}, c.Authority)
		if err != nil {
			return ControlReceipt{}, err
		}
		receipt, err := c.Call(ctx, owner, signed)
		if err != nil {
			return ControlReceipt{}, err
		}
		if receipt.Owner != owner {
			return ControlReceipt{}, errors.New("receipt from wrong member")
		}
		if err := VerifyControlReceipt(receipt, plan, ed25519.PublicKey(keys[owner])); err != nil {
			return ControlReceipt{}, err
		}
		return receipt, nil
	}
	prepared := make([]ControlReceipt, 0, len(owners))
	for _, owner := range owners {
		receipt, exists := receipts[owner]
		if exists {
			if receipt.Owner != owner {
				return empty, false, errors.New("stored receipt owner mismatch")
			}
			if err := VerifyControlReceipt(receipt, plan, ed25519.PublicKey(keys[owner])); err != nil {
				return empty, false, err
			}
		} else {
			var err error
			receipt, err = request(owner, "prepare", nil, nil)
			if err != nil {
				return empty, false, err
			}
			receipts[owner] = receipt
			body, _ := json.Marshal(receipts)
			if err := c.save(&job, map[string]any{"receipts_json": string(body)}); err != nil {
				return empty, false, err
			}
		}
		prepared = append(prepared, receipt)
	}
	var policy Policy
	if job.PolicyJSON != "" {
		if err := json.Unmarshal([]byte(job.PolicyJSON), &policy); err != nil {
			return empty, false, err
		}
		if policy.Subscription != plan.Subscription || policy.Epoch != plan.NextEpoch || policy.Limit != target.Limit || policy.ExpiresAt != target.ExpiresAt || policy.Mode != target.Mode || !reflect.DeepEqual(policy.Keys, keys) {
			return empty, false, errors.New("stored coordinator policy mismatch")
		}
		if _, err := New(policy); err != nil {
			return empty, false, err
		}
		if target.Eventual && (policy.Version != 1 || policy.Manager != c.Owner || policy.Disabled != target.Disabled || policy.Unlimited != target.Unlimited || !reflect.DeepEqual(policy.Authority, []byte(c.Authority.Public().(ed25519.PublicKey)))) {
			return empty, false, errors.New("stored lifecycle policy differs from enrollment target")
		}
		if policy.ControlEpoch != c.ControlEpoch || !reflect.DeepEqual(policy.ControlKeys, c.ControlKeys) {
			return empty, false, errors.New("stored enrollment control membership mismatch")
		}
	} else {
		var billed int64
		switch plan.Kind {
		case "enroll":
			if c.InitialUsage == nil && len(plan.AccountingRoots) == 0 {
				return empty, false, errors.New("authoritative frozen historical usage required")
			}
			var err error
			if len(plan.AccountingRoots) != 0 {
				billed, err = PreparedHistoricalUsage(plan, prepared)
			} else {
				billed, err = c.InitialUsage(ctx, plan, prepared)
			}
			if err != nil {
				return empty, false, err
			}
		case "renew", "reset":
			var err error
			billed, err = finalPreparedUsage(plan, prior, prepared)
			if err != nil {
				return empty, false, err
			}
			if plan.Kind == "reset" {
				billed = 0
			}
		}
		if billed < 0 {
			return empty, false, errors.New("negative historical usage")
		}
		policy = Policy{Subscription: plan.Subscription, Epoch: plan.NextEpoch, Limit: target.Limit, AlreadyBilled: billed, ExpiresAt: target.ExpiresAt, Keys: keys, Grants: allocateRights(target.Limit-min(target.Limit, billed), owners, target.Weights)}
		policy.Mode = target.Mode
		if policy.Mode == "shared" {
			for owner := range policy.Grants {
				policy.Grants[owner] = 0
			}
			if target.Eventual {
				policy.Version, policy.ResetGeneration = 1, 1
				policy.Authority = clone([]byte(c.Authority.Public().(ed25519.PublicKey)))
				policy.Manager = c.Owner
				policy.Disabled, policy.Unlimited = target.Disabled, target.Unlimited
				policy.ControlEpoch, policy.ControlKeys = c.ControlEpoch, clone(c.ControlKeys)
			}
		}
		if _, err := New(policy); err != nil {
			return empty, false, err
		}
		body, _ := json.Marshal(policy)
		if err := c.save(&job, map[string]any{"policy_json": string(body)}); err != nil {
			return empty, false, err
		}
	}
	if policy.ControlEpoch != "" {
		if c.RegisterPolicy == nil {
			return policy, false, errors.New("majority registration unavailable")
		}
		if err := c.RegisterPolicy(ctx, policy); err != nil {
			return policy, false, err
		}
	}
	for _, owner := range owners {
		if acknowledged[owner] {
			continue
		}
		receipt, err := request(owner, "commit", &policy, prepared)
		if err != nil {
			return policy, false, err
		}
		if !reflect.DeepEqual(receipt, receipts[owner]) {
			return policy, false, errors.New("commit replaced prepared receipt")
		}
		acknowledged[owner] = true
		body, _ := json.Marshal(acknowledged)
		if err := c.save(&job, map[string]any{"acknowledged_json": string(body)}); err != nil {
			return policy, false, err
		}
	}
	if !job.Complete {
		if err := c.save(&job, map[string]any{"complete": true}); err != nil {
			return policy, false, err
		}
	}
	return policy, true, nil
}

func finalPreparedUsage(plan ControlPlan, prior *Policy, receipts []ControlReceipt) (int64, error) {
	if prior == nil || prior.Subscription != plan.Subscription || prior.Epoch != plan.Epoch || len(prior.Keys) != len(receipts) {
		return 0, errors.New("missing prior membership")
	}
	ledger, err := New(*prior)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, receipt := range receipts {
		proof := receipt.Freeze
		if proof == nil || seen[proof.Owner] || proof.Owner != receipt.Owner || proof.Subscription != plan.Subscription || proof.Epoch != plan.Epoch || proof.NextEpoch != plan.NextEpoch || proof.Transition != plan.ID {
			return 0, errors.New("invalid freeze scope")
		}
		key := prior.Keys[proof.Owner]
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, freezePayload(*proof), proof.Signature) {
			return 0, errors.New("invalid freeze signature")
		}
		seen[proof.Owner] = true
		if err := ledger.Merge(proof.Rows); err != nil {
			return 0, err
		}
	}
	return ledger.Billed()
}

func allocateRights(remaining int64, owners []string, weights map[string]int64) map[string]int64 {
	out := map[string]int64{}
	total := new(big.Int)
	for _, owner := range owners {
		w, explicit := weights[owner]
		if !explicit {
			w = 1
		}
		total.Add(total, big.NewInt(w))
	}
	left := remaining
	if total.Sign() == 0 {
		for _, owner := range owners {
			out[owner] = 0
		}
		return out
	}
	for _, owner := range owners {
		w, explicit := weights[owner]
		if !explicit {
			w = 1
		}
		n := new(big.Int).Mul(big.NewInt(remaining), big.NewInt(w))
		n.Div(n, total)
		out[owner] = n.Int64()
		left -= out[owner]
	}
	for _, owner := range owners {
		if left == 0 {
			break
		}
		if w, explicit := weights[owner]; explicit && w == 0 {
			continue
		}
		out[owner]++
		left--
	}
	return out
}
