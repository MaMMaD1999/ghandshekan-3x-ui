package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MeshControl is reachable only on the private mTLS listener. An independently
// pinned authority must also sign every command. A node certificate/usage key
// cannot enroll subscribers, reset a cycle, or mint spending rights.
type MeshControl struct {
	DB               *gorm.DB
	Owner            string
	Key              ed25519.PrivateKey
	Authority        ed25519.PublicKey
	Enforcer         *MeshEnforcer
	Drain            func(context.Context, []string) error
	Flush            func(context.Context) error
	Checkpoint       func() error
	ScopedCheckpoint func(string) error
}

func (c *MeshControl) transaction(fn func(*gorm.DB) error) error {
	return submitTrafficWrite(func() error { return c.DB.Transaction(fn) })
}

// MeshAliasFingerprint deliberately includes protocol credentials and exact
// local associations. Shared nodes serving two masters cannot silently claim
// somebody else's email. Secrets stay server-side; only their digest is sent.
func MeshAliasFingerprint(db *gorm.DB, email string) (string, error) {
	var client model.ClientRecord
	if err := db.First(&client, "email = ?", email).Error; err != nil {
		return "", err
	}
	var inbounds []model.Inbound
	if err := db.Table("inbounds").Select("inbounds.*").Joins("JOIN client_inbounds ON client_inbounds.inbound_id = inbounds.id").Where("client_inbounds.client_id = ?", client.Id).Order("inbounds.id").Find(&inbounds).Error; err != nil {
		return "", err
	}
	if len(inbounds) == 0 {
		return "", errors.New("alias has no inbound")
	}
	type attachment struct {
		ID         int
		Tag        string
		Protocol   model.Protocol
		Credential map[string]any
		Node       *int
		NodeOwner  string
	}
	attachments := make([]attachment, 0, len(inbounds))
	for _, inbound := range inbounds {
		nodeOwner := ""
		if inbound.NodeID != nil {
			var node model.Node
			if err := db.Select("guid").First(&node, "id = ?", *inbound.NodeID).Error; err != nil {
				return "", err
			}
			if node.Guid == "" {
				return "", errors.New("remote inbound has no stable panel identity")
			}
			nodeOwner = node.Guid
		}
		if inbound.Protocol != "vless" && inbound.Protocol != "vmess" && inbound.Protocol != "trojan" {
			return "", errors.New("protocol has not passed mesh drain acceptance")
		}
		var settings struct {
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return "", err
		}
		var credential map[string]any
		for _, entry := range settings.Clients {
			if entry["email"] != email {
				continue
			}
			if credential != nil {
				return "", errors.New("duplicate runtime alias")
			}
			credential = map[string]any{}
			for _, key := range []string{"email", "id", "password", "auth", "security", "flow"} {
				if v, ok := entry[key]; ok {
					credential[key] = v
				}
			}
		}
		if credential == nil {
			return "", errors.New("runtime alias missing")
		}
		attachments = append(attachments, attachment{inbound.Id, inbound.Tag, inbound.Protocol, credential, inbound.NodeID, nodeOwner})
	}
	encoded, _ := json.Marshal(struct {
		Email, SubID, UUID, Password, Auth string
		Attachments                        []attachment
	}{client.Email, client.SubID, client.UUID, client.Password, client.Auth, attachments})
	hash := sha256.Sum256(append([]byte("ghandshekan/local-alias/v1\x00"), encoded...))
	return hex.EncodeToString(hash[:]), nil
}

func meshPendingAliases(db *gorm.DB) (map[string]bool, error) {
	result := map[string]bool{}
	// Older test/legacy schemas may not contain the opt-in control table. Live
	// migrations create it before the runtime; checkpoint validation detects its
	// disappearance once a command has ever been accepted.
	if !db.Migrator().HasTable(&model.MeshControlState{}) {
		return result, nil
	}
	var rows []model.MeshControlState
	if err := db.Where("stage < ?", 2).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		var plan quotaescrow.ControlPlan
		if err := json.Unmarshal([]byte(row.PlanJSON), &plan); err != nil {
			return nil, err
		}
		if err := plan.Validate(); err != nil {
			return nil, err
		}
		if row.ID != plan.ID || row.Subscription != plan.Subscription || row.PlanHash != quotaescrow.ControlPlanHash(plan) {
			return nil, errors.New("invalid durable control barrier")
		}
		// Only aliases present on this host are included; the immutable plan is
		// shared between owners but its local barriers are stored individually.
		var receiptOwner struct {
			Owner string `json:"owner"`
		}
		if err := json.Unmarshal([]byte(row.ReceiptJSON), &receiptOwner); err != nil {
			return nil, err
		}
		claims := plan.Claims[receiptOwner.Owner]
		if len(claims) == 0 {
			return nil, errors.New("barrier has no local owner")
		}
		for _, claim := range claims {
			result[claim.Email] = true
		}
	}
	if db.Migrator().HasTable(&quotaescrow.Record{}) {
		var shared []quotaescrow.Record
		if err := db.Where("pending_updates_json <> ? AND pending_updates_json <> ?", "[]", "").Find(&shared).Error; err != nil {
			return nil, err
		}
		for _, r := range shared {
			if err := quotaescrow.ValidateCheckpointAdvance(r, r, nil); err != nil {
				return nil, err
			}
			var bindings []model.MeshBinding
			if err := db.Where("subscription = ?", r.Subscription).Find(&bindings).Error; err != nil {
				return nil, err
			}
			for _, b := range bindings {
				result[b.Email] = true
			}
		}
	}
	return result, nil
}

func (c *MeshControl) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mutual TLS required", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		var signed quotaescrow.SignedControl
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&signed) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid control request", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		receipt, err := c.Execute(ctx, signed)
		if err != nil {
			http.Error(w, "control not committed; existing barrier is retained", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}

func (c *MeshControl) Execute(ctx context.Context, signed quotaescrow.SignedControl) (quotaescrow.ControlReceipt, error) {
	var empty quotaescrow.ControlReceipt
	if c.DB == nil || c.Enforcer == nil || c.Drain == nil || c.Flush == nil || c.Checkpoint == nil || len(c.Key) != ed25519.PrivateKeySize {
		return empty, errors.New("control adapter unavailable")
	}
	command, err := quotaescrow.VerifyControl(signed, c.Authority, c.Owner, time.Now().Unix())
	if err != nil {
		return empty, err
	}
	c.Enforcer.mu.Lock()
	defer c.Enforcer.mu.Unlock()
	if err := c.Checkpoint(); err != nil {
		return empty, err
	}
	plan := command.Plan
	claims := plan.Claims[c.Owner]
	emails := make([]string, 0, len(claims))
	for _, claim := range claims {
		fingerprint, err := MeshAliasFingerprint(c.DB, claim.Email)
		if err != nil {
			return empty, err
		}
		if fingerprint != claim.Fingerprint {
			return empty, errors.New("client ownership/credential changed")
		}
		emails = append(emails, claim.Email)
	}
	if command.Operation == "commit" {
		return c.commit(ctx, command, emails)
	}
	encoded, _ := json.Marshal(plan)
	placeholder, _ := json.Marshal(quotaescrow.ControlReceipt{Owner: c.Owner})
	var state model.MeshControlState
	err = c.transaction(func(tx *gorm.DB) error {
		err := tx.First(&state, "id = ?", plan.ID).Error
		if err == nil {
			if state.PlanHash != quotaescrow.ControlPlanHash(plan) {
				return errors.New("operation ID already used")
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		pending, err := meshPendingAliases(tx)
		if err != nil {
			return err
		}
		for _, email := range emails {
			if pending[email] {
				return errors.New("alias already has a pending transition")
			}
		}
		var bindings []model.MeshBinding
		if err := tx.Where("email IN ? OR subscription = ?", emails, plan.Subscription).Find(&bindings).Error; err != nil {
			return err
		}
		if plan.Kind == "enroll" {
			if len(bindings) > 0 {
				return errors.New("alias is already enrolled")
			}
			// Reject known ambiguous legacy state before fencing a healthy user.
			// The signed snapshot is captured again after the final drain.
			if _, err := CaptureMeshHistorical(tx, c.Owner, emails); err != nil {
				return err
			}
			var count int64
			if err := tx.Model(&quotaescrow.Record{}).Where("subscription = ?", plan.Subscription).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return errors.New("subscription already exists")
			}
		} else {
			if len(bindings) != len(emails) {
				return errors.New("all local aliases must participate")
			}
			for _, b := range bindings {
				if b.Subscription != plan.Subscription || b.Owner != c.Owner || !slices.Contains(emails, b.Email) {
					return errors.New("binding ownership mismatch")
				}
			}
			var record quotaescrow.Record
			if err := tx.First(&record, "subscription = ?", plan.Subscription).Error; err != nil {
				return err
			}
			var old quotaescrow.Policy
			if json.Unmarshal([]byte(record.PolicyJSON), &old) != nil || old.Epoch != plan.Epoch || len(old.Keys) != len(plan.Claims) {
				return errors.New("previous epoch/membership mismatch")
			}
			for owner := range old.Keys {
				if len(plan.Claims[owner]) == 0 {
					return errors.New("previous member cannot be omitted")
				}
			}
			if err := quotaescrow.NewStore(tx).BeginTransition(plan.Subscription, plan.NextEpoch, plan.ID); err != nil {
				return err
			}
		}
		if err := quotaescrow.InitializeClock(tx, time.Now()); err != nil {
			return err
		}
		state = model.MeshControlState{ID: plan.ID, Subscription: plan.Subscription, PlanHash: quotaescrow.ControlPlanHash(plan), PlanJSON: string(encoded), ReceiptJSON: string(placeholder)}
		return tx.Create(&state).Error
	})
	if err != nil {
		return empty, err
	}
	if err := c.Checkpoint(); err != nil {
		return empty, err
	}
	if state.Stage >= 1 {
		if err := json.Unmarshal([]byte(state.ReceiptJSON), &empty); err != nil {
			return quotaescrow.ControlReceipt{}, err
		}
		return empty, nil
	}
	blocked, err := MeshBlockedEmails(c.DB, time.Now().Unix())
	if err != nil {
		return empty, err
	}
	if err := c.Enforcer.apply(ctx, blocked); err != nil {
		return empty, err
	}
	if err := c.Drain(ctx, emails); err != nil {
		return empty, err
	}
	if err := c.Flush(ctx); err != nil {
		return empty, err
	}
	receipt := quotaescrow.ControlReceipt{PlanHash: state.PlanHash, Owner: c.Owner, Local: map[string]int64{}, Sources: map[string]string{}}
	err = c.transaction(func(tx *gorm.DB) error {
		store := quotaescrow.NewStore(tx)
		if plan.Kind == "enroll" {
			historical, err := CaptureMeshHistorical(tx, c.Owner, emails)
			if err != nil {
				return err
			}
			receipt.Historical = &historical
		}
		for _, email := range emails {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.LocalUsage{Email: email, Source: rand.Text()}).Error; err != nil {
				return err
			}
			var local model.LocalUsage
			if err := tx.First(&local, "email = ?", email).Error; err != nil {
				return err
			}
			if local.Source == "" || local.Billed < 0 {
				return errors.New("invalid local baseline")
			}
			receipt.Local[email] = local.Billed
			receipt.Sources[email] = local.Source
			if plan.Kind != "enroll" {
				if err := store.ObserveMeter(plan.Subscription, c.Owner, local.Source, c.Key, local.Billed); err != nil {
					return err
				}
			}
		}
		if plan.Kind != "enroll" {
			proof, err := store.Freeze(plan.Subscription, c.Owner, plan.NextEpoch, plan.ID, c.Key)
			if err != nil {
				return err
			}
			receipt.Freeze = &proof
		}
		var err error
		receipt, err = quotaescrow.SignControlReceipt(receipt, c.Key)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(receipt)
		return tx.Model(&model.MeshControlState{}).Where("id = ? AND stage = ?", plan.ID, 0).Updates(map[string]any{"stage": 1, "receipt_json": string(body)}).Error
	})
	if err != nil {
		return empty, err
	}
	if err := c.Checkpoint(); err != nil {
		return empty, err
	}
	return receipt, nil
}

func (c *MeshControl) commit(ctx context.Context, command quotaescrow.ControlCommand, emails []string) (quotaescrow.ControlReceipt, error) {
	var result quotaescrow.ControlReceipt
	plan, p := command.Plan, *command.Policy
	if p.Version > 0 && !bytes.Equal(p.Authority, c.Authority) {
		return result, errors.New("shared lifecycle authority changed")
	}
	if !bytes.Equal(p.Keys[c.Owner], c.Key.Public().(ed25519.PublicKey)) {
		return result, errors.New("local key changed")
	}
	var state model.MeshControlState
	if err := c.DB.First(&state, "id = ?", plan.ID).Error; err != nil {
		return result, err
	}
	if state.Stage < 1 || state.PlanHash != quotaescrow.ControlPlanHash(plan) {
		return result, errors.New("operation not prepared")
	}
	if err := json.Unmarshal([]byte(state.ReceiptJSON), &result); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	proofs := make([]quotaescrow.FreezeProof, 0, len(command.Receipts))
	for _, receipt := range command.Receipts {
		if seen[receipt.Owner] {
			return result, errors.New("duplicate prepared member")
		}
		seen[receipt.Owner] = true
		if err := quotaescrow.VerifyControlReceipt(receipt, plan, ed25519.PublicKey(p.Keys[receipt.Owner])); err != nil {
			return result, err
		}
		if receipt.Owner == c.Owner && !reflect.DeepEqual(receipt, result) {
			return result, errors.New("local prepared receipt changed")
		}
		if receipt.Freeze != nil {
			proofs = append(proofs, *receipt.Freeze)
		}
	}
	if len(plan.AccountingRoots) != 0 {
		billed, err := quotaescrow.PreparedHistoricalUsage(plan, command.Receipts)
		if err != nil {
			return result, err
		}
		if billed != p.AlreadyBilled {
			return result, errors.New("enrollment does not preserve frozen historical usage")
		}
	}
	canonicalReceipts := slices.Clone(command.Receipts)
	slices.SortFunc(canonicalReceipts, func(a, b quotaescrow.ControlReceipt) int { return strings.Compare(a.Owner, b.Owner) })
	body, _ := json.Marshal(struct {
		Policy   quotaescrow.Policy
		Receipts []quotaescrow.ControlReceipt
	}{p, canonicalReceipts})
	digest := sha256.Sum256(body)
	commitHash := hex.EncodeToString(digest[:])
	if state.Stage == 2 {
		if state.CommitHash != commitHash {
			return result, errors.New("completed commit differs")
		}
		return result, nil
	}
	// Recheck the barrier and collector even on a process restart. A prepared
	// receipt cannot justify ignoring an unexpected late byte or a new source.
	blocked, err := MeshBlockedEmails(c.DB, time.Now().Unix())
	if err != nil {
		return result, err
	}
	if err := c.Enforcer.apply(ctx, blocked); err != nil {
		return result, err
	}
	if err := c.Drain(ctx, emails); err != nil {
		return result, err
	}
	if err := c.Flush(ctx); err != nil {
		return result, err
	}
	err = c.transaction(func(tx *gorm.DB) error {
		meters := make([]quotaescrow.Meter, 0, len(emails))
		for _, email := range emails {
			var local model.LocalUsage
			if err := tx.First(&local, "email = ?", email).Error; err != nil {
				return err
			}
			if local.Billed != result.Local[email] || local.Source != result.Sources[email] {
				return errors.New("meter moved after prepared drain")
			}
			meters = append(meters, quotaescrow.Meter{Subscription: p.Subscription, Owner: c.Owner, Source: local.Source, Epoch: p.Epoch, Watermark: local.Billed})
		}
		if plan.Kind == "enroll" {
			if err := ActivateMeshMeters(tx, p, c.Owner, emails); err != nil {
				return err
			}
		} else {
			if err := quotaescrow.NewStore(tx).CommitTransition(p, plan.Kind, proofs, meters); err != nil {
				return err
			}
		}
		if err := commitMeshClientPolicy(tx, p, plan.Kind, emails); err != nil {
			return err
		}
		return tx.Model(&model.MeshControlState{}).Where("id = ? AND stage = ?", plan.ID, 1).Updates(map[string]any{"stage": 2, "commit_hash": commitHash}).Error
	})
	if err != nil {
		return result, err
	}
	if err := c.Checkpoint(); err != nil {
		return result, err
	}
	// Reopening is owned by the next supervised enforcement cycle, after its
	// own checkpoint and quota checks. This handler never removes a gate itself.
	return result, nil
}
