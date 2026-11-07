package service

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlog "gorm.io/gorm/logger"
)

var ErrMeshRestore = errors.New("mesh state precedes its independent restore checkpoint")

// The checkpoint database lives outside the panel DB. Restoring x-ui.db must
// not restore spent rights, remove enrollment, or undo a durable pause. This
// detects panel-DB rollback; restoring an entire machine including this file
// still requires reconciliation with surviving peers before admission.
type MeshCheckpoint struct {
	db    *gorm.DB
	key   ed25519.PrivateKey
	owner string
	mu    *sync.Mutex
	// Exact immutable values already validated by this process. Every cycle
	// still reads both databases and compares counters/barriers; a changed
	// byte, signature, epoch or revision requires validation again.
	validatedRecords map[string]quotaescrow.Record
	verifiedEntries  map[string]meshCheckpointEntry
}

type meshCheckpointEntry struct {
	ID        string `gorm:"primaryKey"`
	Body      []byte
	Signature []byte
}

type meshCheckpointState struct {
	Record   quotaescrow.Record
	Bindings []model.MeshBinding
	Local    map[string]model.LocalUsage
	Meters   map[string]quotaescrow.Meter
}

var checkpointLocks sync.Map

func checkpointSignedPayload(owner, id string, body []byte) []byte {
	encoded, _ := json.Marshal(struct {
		Owner, ID string
		Body      []byte
	}{owner, id, body})
	return append([]byte("ghandshekan/restore-checkpoint/v1\x00"), encoded...)
}

// initialize is allowed only behind an explicit enrollment/restore barrier.
// Normal startup cannot silently bless existing accounting with no checkpoint.
func OpenMeshCheckpoint(source *gorm.DB, c *MeshConfig, initialize bool) (*MeshCheckpoint, error) {
	if source == nil || c == nil || c.Owner == "" || !filepath.IsAbs(c.StateDir) || len(c.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrMeshRestore
	}
	if !bytes.Equal(c.PrivateKey, ed25519.NewKeyFromSeed(ed25519.PrivateKey(c.PrivateKey).Seed())) {
		return nil, ErrMeshRestore
	}
	path := filepath.Join(c.StateDir, "checkpoint.sqlite")
	mutex, _ := checkpointLocks.LoadOrStore(path, new(sync.Mutex))
	mu := mutex.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	info, err := os.Lstat(path)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return nil, errors.Join(ErrMeshRestore, err)
	}
	if created {
		var count int64
		if err := source.Model(&quotaescrow.Record{}).Count(&count).Error; err != nil {
			return nil, err
		}
		if source.Migrator().HasTable(&model.MeshControlState{}) {
			var controlCount int64
			if err := source.Model(&model.MeshControlState{}).Count(&controlCount).Error; err != nil {
				return nil, err
			}
			count += controlCount
		}
		if count > 0 && !initialize {
			return nil, errors.Join(ErrMeshRestore, errors.New("checkpoint missing for enrolled accounting"))
		}
		if err := os.MkdirAll(c.StateDir, 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.Join(ErrMeshRestore, errors.New("checkpoint must be a private regular file"))
	}
	db, err := gorm.Open(sqlite.Open(path+"?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=10000"), &gorm.Config{Logger: gormlog.Default.LogMode(gormlog.Silent)})
	if err != nil {
		return nil, errors.Join(ErrMeshRestore, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	cp := &MeshCheckpoint{db: db, key: ed25519.PrivateKey(c.PrivateKey), owner: c.Owner, mu: mu}
	failed := true
	defer func() {
		if failed {
			sqlDB.Close()
		}
	}()
	if created {
		if err := db.AutoMigrate(&meshCheckpointEntry{}); err != nil {
			return nil, err
		}
		entry := cp.signed("identity", []byte(c.Owner))
		if err := db.Create(&entry).Error; err != nil {
			return nil, err
		}
	} else {
		var identity meshCheckpointEntry
		if err := db.First(&identity, "id = ?", "identity").Error; err != nil || !cp.verify(identity) || string(identity.Body) != c.Owner {
			return nil, errors.Join(ErrMeshRestore, errors.New("checkpoint identity unavailable or invalid"))
		}
	}
	if err := cp.advanceLocked(source, ""); err != nil {
		return nil, err
	}
	failed = false
	return cp, nil
}

func (c *MeshCheckpoint) Close() error {
	db, err := c.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
func (c *MeshCheckpoint) signed(id string, body []byte) meshCheckpointEntry {
	return meshCheckpointEntry{ID: id, Body: body, Signature: ed25519.Sign(c.key, checkpointSignedPayload(c.owner, id, body))}
}
func (c *MeshCheckpoint) verify(entry meshCheckpointEntry) bool {
	if prior, ok := c.verifiedEntries[entry.ID]; ok && bytes.Equal(prior.Body, entry.Body) && bytes.Equal(prior.Signature, entry.Signature) {
		return true
	}
	if !ed25519.Verify(c.key.Public().(ed25519.PublicKey), checkpointSignedPayload(c.owner, entry.ID, entry.Body), entry.Signature) {
		return false
	}
	if c.verifiedEntries == nil {
		c.verifiedEntries = map[string]meshCheckpointEntry{}
	}
	c.verifiedEntries[entry.ID] = meshCheckpointEntry{ID: entry.ID, Body: bytes.Clone(entry.Body), Signature: bytes.Clone(entry.Signature)}
	return true
}
func (c *MeshCheckpoint) Advance(source *gorm.DB) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.advanceLocked(source, "")
}

// AdvanceSubscription protects an individual publication without scanning every
// subscriber for every peer exchange. Startup, control changes and enforcement
// still run the complete checkpoint including all membership barriers.
func (c *MeshCheckpoint) AdvanceSubscription(source *gorm.DB, subscription string) error {
	if subscription == "" {
		return errors.New("checkpoint scope required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.advanceLocked(source, subscription)
}

func (c *MeshCheckpoint) advanceLocked(source *gorm.DB, scope string) error {
	states := map[string]meshCheckpointState{}
	controls := map[string]model.MeshControlState{}
	archives := map[[2]string]quotaescrow.EpochArchive{}
	var clock quotaescrow.ClockState
	err := source.Transaction(func(tx *gorm.DB) error {
		if scope == "" && tx.Migrator().HasTable(&model.MeshControlState{}) {
			var pending []model.MeshControlState
			if err := tx.Find(&pending).Error; err != nil {
				return err
			}
			for _, state := range pending {
				if err := c.validateControlCheckpoint(state); err != nil {
					return err
				}
				controls[state.ID] = state
			}
		}
		var records []quotaescrow.Record
		scoped := func(query *gorm.DB) *gorm.DB {
			if scope != "" {
				return query.Where("subscription = ?", scope)
			}
			return query
		}
		if err := scoped(tx).Find(&records).Error; err != nil {
			return err
		}
		if scope != "" && len(records) != 1 {
			return errors.New("scoped checkpoint policy missing")
		}
		for _, record := range records {
			if prior, ok := c.validatedRecords[record.Subscription]; !ok || prior != record {
				if err := quotaescrow.ValidateCheckpointAdvance(record, record, nil); err != nil {
					return err
				}
			}
			states[record.Subscription] = meshCheckpointState{Record: record, Local: map[string]model.LocalUsage{}, Meters: map[string]quotaescrow.Meter{}}
		}
		var bindings []model.MeshBinding
		if err := scoped(tx).Order("email").Find(&bindings).Error; err != nil {
			return err
		}
		for _, binding := range bindings {
			state, ok := states[binding.Subscription]
			if !ok || binding.Owner != c.owner {
				return errors.New("checkpoint binding has no local policy")
			}
			state.Bindings = append(state.Bindings, binding)
			states[binding.Subscription] = state
		}
		var local []model.LocalUsage
		localQuery := tx.Model(&model.LocalUsage{})
		if scope != "" {
			localQuery = localQuery.Where("email IN (?)", tx.Model(&model.MeshBinding{}).Select("email").Where("subscription = ?", scope))
		}
		if err := localQuery.Find(&local).Error; err != nil {
			return err
		}
		byEmail := map[string]model.LocalUsage{}
		for _, counter := range local {
			byEmail[counter.Email] = counter
		}
		var meters []quotaescrow.Meter
		if err := scoped(tx).Where("owner = ?", c.owner).Find(&meters).Error; err != nil {
			return err
		}
		byMeter := map[[2]string]quotaescrow.Meter{}
		for _, meter := range meters {
			byMeter[[2]string{meter.Subscription, meter.Source}] = meter
		}
		for subscription, state := range states {
			var policy quotaescrow.Policy
			if err := json.Unmarshal([]byte(state.Record.PolicyJSON), &policy); err != nil {
				return err
			}
			if len(state.Bindings) == 0 {
				return errors.New("checkpoint policy has no bindings")
			}
			for _, binding := range state.Bindings {
				counter, ok := byEmail[binding.Email]
				if !ok || counter.Source == "" || counter.Billed < 0 {
					return errors.New("checkpoint local meter missing")
				}
				state.Local[binding.Email] = counter
				meter, exists := byMeter[[2]string{subscription, counter.Source}]
				if !exists {
					return errors.New("checkpoint meter missing")
				}
				if meter.Epoch != policy.Epoch || meter.Watermark < 0 || meter.Watermark > counter.Billed {
					return errors.New("invalid checkpoint meter baseline")
				}
				state.Meters[binding.Email] = meter
			}
			states[subscription] = state
		}
		if len(states) > 0 || len(controls) > 0 {
			if err := tx.First(&clock, "id = ?", "local").Error; err != nil {
				return err
			}
			if clock.LastUnix <= 0 {
				return errors.New("invalid checkpoint clock")
			}
		}
		var rows []quotaescrow.EpochArchive
		if err := scoped(tx).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			archives[[2]string{row.Subscription, row.Epoch}] = row
		}
		return nil
	})
	if err != nil {
		return errors.Join(ErrMeshRestore, err)
	}
	err = c.db.Transaction(func(tx *gorm.DB) error {
		var floors []meshCheckpointEntry
		floorQuery := tx.Where("id <> ?", "identity")
		if scope != "" {
			floorQuery = tx.Where("id IN ?", []string{"clock", "sub:" + scope})
		}
		if err := floorQuery.Find(&floors).Error; err != nil {
			return err
		}
		previous := map[string][]byte{}
		previousControls := map[string][]byte{}
		for _, floor := range floors {
			if !c.verify(floor) {
				return errors.New("checkpoint signature invalid")
			}
			if floor.ID == "clock" {
				var prior quotaescrow.ClockState
				if err := json.Unmarshal(floor.Body, &prior); err != nil {
					return err
				}
				if clock.LastUnix < prior.LastUnix {
					return errors.New("clock precedes checkpoint")
				}
				continue
			}
			if strings.HasPrefix(floor.ID, "control:") {
				id := strings.TrimPrefix(floor.ID, "control:")
				var old model.MeshControlState
				if err := json.Unmarshal(floor.Body, &old); err != nil {
					return err
				}
				current, ok := controls[id]
				if !ok || old.ID != id || current.PlanHash != old.PlanHash || current.PlanJSON != old.PlanJSON || current.Subscription != old.Subscription || current.Stage < old.Stage || (old.Stage >= 1 && current.ReceiptJSON != old.ReceiptJSON) || (old.Stage == 2 && current.CommitHash != old.CommitHash) {
					return errors.New("control barrier precedes checkpoint")
				}
				previousControls[id] = floor.Body
				continue
			}
			if !strings.HasPrefix(floor.ID, "sub:") {
				return errors.New("unknown checkpoint entry")
			}
			subscription := strings.TrimPrefix(floor.ID, "sub:")
			var old meshCheckpointState
			if err := json.Unmarshal(floor.Body, &old); err != nil {
				return err
			}
			current, ok := states[subscription]
			if !ok || old.Record.Subscription != subscription {
				return errors.New("enrolled subscription disappeared after restore")
			}
			var policy quotaescrow.Policy
			if err := json.Unmarshal([]byte(old.Record.PolicyJSON), &policy); err != nil {
				return err
			}
			archive, hasArchive := archives[[2]string{subscription, policy.Epoch}]
			var proof *quotaescrow.EpochArchive
			if hasArchive {
				proof = &archive
			}
			if old.Record != current.Record {
				if err := quotaescrow.ValidateCheckpointAdvance(old.Record, current.Record, proof); err != nil {
					return err
				}
			}
			bindings := map[string]model.MeshBinding{}
			for _, b := range current.Bindings {
				bindings[b.Email] = b
			}
			for _, b := range old.Bindings {
				if bindings[b.Email] != b {
					return errors.New("enrolled alias disappeared or changed owner")
				}
				counter := current.Local[b.Email]
				prior := old.Local[b.Email]
				if counter.Source != prior.Source || counter.Billed < prior.Billed {
					return errors.New("local meter precedes checkpoint")
				}
				meter, exists := current.Meters[b.Email]
				before, known := old.Meters[b.Email]
				if !exists || !known || meter.Watermark < before.Watermark {
					return errors.New("meter watermark precedes checkpoint")
				}
			}
			previous[subscription] = floor.Body
		}
		for subscription, state := range states {
			body, err := json.Marshal(state)
			if err != nil {
				return err
			}
			if bytes.Equal(previous[subscription], body) {
				continue
			}
			entry := c.signed("sub:"+subscription, body)
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&entry).Error; err != nil {
				return err
			}
		}
		for id, state := range controls {
			body, err := json.Marshal(state)
			if err != nil {
				return err
			}
			if bytes.Equal(previousControls[id], body) {
				continue
			}
			entry := c.signed("control:"+id, body)
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&entry).Error; err != nil {
				return err
			}
		}
		if clock.LastUnix > 0 {
			body, err := json.Marshal(clock)
			if err != nil {
				return err
			}
			entry := c.signed("clock", body)
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&entry).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errors.Join(ErrMeshRestore, err)
	}
	if c.validatedRecords == nil {
		c.validatedRecords = map[string]quotaescrow.Record{}
	}
	for subscription, state := range states {
		c.validatedRecords[subscription] = state.Record
	}
	return nil
}

func (c *MeshCheckpoint) validateControlCheckpoint(state model.MeshControlState) error {
	var plan quotaescrow.ControlPlan
	if err := json.Unmarshal([]byte(state.PlanJSON), &plan); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if state.ID != plan.ID || state.Subscription != plan.Subscription || state.PlanHash != quotaescrow.ControlPlanHash(plan) || state.Stage < 0 || state.Stage > 2 || len(plan.Claims[c.owner]) == 0 {
		return errors.New("invalid control checkpoint")
	}
	var receipt quotaescrow.ControlReceipt
	if err := json.Unmarshal([]byte(state.ReceiptJSON), &receipt); err != nil {
		return err
	}
	if receipt.Owner != c.owner {
		return errors.New("foreign control checkpoint")
	}
	if state.Stage > 0 {
		if err := quotaescrow.VerifyControlReceipt(receipt, plan, c.key.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	}
	if state.Stage == 2 && len(state.CommitHash) != 64 {
		return errors.New("missing committed policy digest")
	}
	return nil
}
