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
	if err := cp.advanceLocked(source); err != nil {
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
	return ed25519.Verify(c.key.Public().(ed25519.PublicKey), checkpointSignedPayload(c.owner, entry.ID, entry.Body), entry.Signature)
}
func (c *MeshCheckpoint) Advance(source *gorm.DB) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.advanceLocked(source)
}

func (c *MeshCheckpoint) advanceLocked(source *gorm.DB) error {
	states := map[string]meshCheckpointState{}
	archives := map[[2]string]quotaescrow.EpochArchive{}
	var clock quotaescrow.ClockState
	err := source.Transaction(func(tx *gorm.DB) error {
		var records []quotaescrow.Record
		if err := tx.Find(&records).Error; err != nil {
			return err
		}
		for _, record := range records {
			if err := quotaescrow.ValidateCheckpointAdvance(record, record, nil); err != nil {
				return err
			}
			states[record.Subscription] = meshCheckpointState{Record: record, Local: map[string]model.LocalUsage{}, Meters: map[string]quotaescrow.Meter{}}
		}
		var bindings []model.MeshBinding
		if err := tx.Order("email").Find(&bindings).Error; err != nil {
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
		if err := tx.Find(&local).Error; err != nil {
			return err
		}
		byEmail := map[string]model.LocalUsage{}
		for _, counter := range local {
			byEmail[counter.Email] = counter
		}
		var meters []quotaescrow.Meter
		if err := tx.Where("owner = ?", c.owner).Find(&meters).Error; err != nil {
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
		if len(states) > 0 {
			if err := tx.First(&clock, "id = ?", "local").Error; err != nil {
				return err
			}
			if clock.LastUnix <= 0 {
				return errors.New("invalid checkpoint clock")
			}
		}
		var rows []quotaescrow.EpochArchive
		if err := tx.Find(&rows).Error; err != nil {
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
		if err := tx.Where("id <> ?", "identity").Find(&floors).Error; err != nil {
			return err
		}
		previous := map[string][]byte{}
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
			if err := quotaescrow.ValidateCheckpointAdvance(old.Record, current.Record, proof); err != nil {
				return err
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
	return nil
}
