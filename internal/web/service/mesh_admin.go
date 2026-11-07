package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// MeshAdministrator is installed only on a managing panel. The private signing
// key and durable coordinator journal never pass through browser settings.
type MeshAdministrator struct {
	Coordinator *quotaescrow.Coordinator
	Quorum      *MeshQuorum
	Local       *MeshControl
	wake        chan struct{}
	mu          sync.Mutex
}

var activeMeshAdministrator atomic.Pointer[MeshAdministrator]

type MeshOperationResult struct {
	Operation string `json:"operation"`
	Pending   bool   `json:"pending"`
}

type MeshAvailability struct {
	Disabled  *bool
	Unlimited *bool
}

func OpenMeshAdministrator(config *MeshConfig, local *MeshControl, transport quotaescrow.ControlClient) (*MeshAdministrator, error) {
	if config.AuthorityFile == "" {
		return nil, nil
	}
	f, err := os.Open(config.AuthorityFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 4096 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("private authority file required")
	}
	var secret struct {
		PrivateKey []byte `json:"privateKey"`
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&secret) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid authority file")
	}
	key := ed25519.PrivateKey(secret.PrivateKey)
	if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(config.Authority)) {
		return nil, errors.New("coordinator authority mismatch")
	}
	if strings.ContainsAny(config.JournalFile, "?\r\n") {
		return nil, errors.New("invalid coordinator journal path")
	}
	dir, err := os.Stat(filepath.Dir(config.JournalFile))
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() || (runtime.GOOS != "windows" && dir.Mode().Perm()&0077 != 0) {
		return nil, errors.New("coordinator journal directory must be private")
	}
	jf, err := os.OpenFile(config.JournalFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	js, err := jf.Stat()
	_ = jf.Close()
	if err != nil {
		return nil, err
	}
	if !js.Mode().IsRegular() || (runtime.GOOS != "windows" && js.Mode().Perm()&0077 != 0) {
		return nil, errors.New("coordinator journal must be private")
	}
	db, err := gorm.Open(sqlite.Open(config.JournalFile+"?_busy_timeout=10000&_journal_mode=WAL&_synchronous=FULL&_txlock=immediate"), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		return nil, err
	}
	pool, err := db.DB()
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		_ = pool.Close()
		return nil, err
	}
	builder := quotaescrow.PlanBuilder{Authority: key, Keys: config.PeerKeys, Inspect: transport.Inspect}
	coordinator := &quotaescrow.Coordinator{Owner: config.Owner, DB: db, Authority: key, Call: transport.Execute, CheckReady: builder.CheckReady, UpdatePolicy: transport.UpdatePolicy}
	return &MeshAdministrator{Coordinator: coordinator, Local: local, wake: make(chan struct{}, 1)}, nil
}

func (a *MeshAdministrator) Close() {
	if a == nil {
		return
	}
	activeMeshAdministrator.CompareAndSwap(a, nil)
	if a.Quorum != nil {
		a.Quorum.Close()
		return
	}
	if db, err := a.Coordinator.DB.DB(); err == nil {
		_ = db.Close()
	}
}

func (a *MeshAdministrator) Run(ctx context.Context) {
	if a.Quorum != nil {
		lastLog := time.Time{}
		for ctx.Err() == nil {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			if err := a.Quorum.SyncCycle(bounded); err != nil && ctx.Err() == nil && time.Since(lastLog) > time.Minute {
				logger.Warning("mesh control catch-up: ", err)
				lastLog = time.Now()
			}
			cancel()
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		return
	}
	cursor := ""
	for ctx.Err() == nil {
		next, _, err := a.Coordinator.RecoverPending(ctx, cursor, 8, 30*time.Second)
		if err == nil {
			cursor = next
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-a.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func meshOperationID(subscription, kind, key string) (string, error) {
	if key == "" {
		key = rand.Text()
	}
	if len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		return "", errors.New("invalid lifecycle idempotency key")
	}
	hash := sha256.Sum256([]byte(subscription + "\x00" + kind + "\x00" + key))
	return "panel-" + hex.EncodeToString(hash[:]), nil
}

func (a *MeshAdministrator) Queue(ctx context.Context, subscription, kind, key string, limit, expiry *int64, availability ...MeshAvailability) (MeshOperationResult, error) {
	if a.Quorum != nil {
		return a.Quorum.Queue(ctx, subscription, kind, key, limit, expiry, availability...)
	}
	var result MeshOperationResult
	id, err := meshOperationID(subscription, kind, key)
	if err != nil {
		return result, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var job quotaescrow.ControlJob
	err = a.Coordinator.DB.First(&job, "id = ?", id).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return result, err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var jobs []quotaescrow.ControlJob
		if err := a.Coordinator.DB.Where("subscription = ? AND policy_json <> ?", subscription, "").Find(&jobs).Error; err != nil {
			return result, err
		}
		var latest quotaescrow.Policy
		var previous quotaescrow.ControlPlan
		for _, j := range jobs {
			var p quotaescrow.Policy
			if json.Unmarshal([]byte(j.PolicyJSON), &p) != nil {
				return result, errors.New("invalid coordinator policy")
			}
			if p.Version > latest.Version {
				if p.Version == 1 && !j.Complete {
					return result, errors.New("subscription enrollment is incomplete")
				}
				latest = p
				if err := json.Unmarshal([]byte(j.PlanJSON), &previous); err != nil {
					return result, err
				}
			}
		}
		if latest.Version == 0 || latest.Manager != a.Local.Owner {
			return result, errors.New("subscription must be changed on its managing panel")
		}
		builder := quotaescrow.PlanBuilder{Authority: a.Coordinator.Authority, Keys: latest.Keys}
		plan, err := builder.Transition(ctx, kind, previous, latest)
		if err != nil {
			return result, err
		}
		plan.ID = id
		target := quotaescrow.ControlTarget{Mode: "shared", Eventual: true, Limit: latest.Limit, ExpiresAt: latest.ExpiresAt, Disabled: latest.Disabled, Unlimited: latest.Unlimited}
		if len(availability) > 1 {
			return result, errors.New("invalid availability options")
		}
		if len(availability) == 1 {
			if availability[0].Disabled != nil {
				target.Disabled = *availability[0].Disabled
			}
			if availability[0].Unlimited != nil {
				target.Unlimited = *availability[0].Unlimited
			}
		}
		if limit != nil {
			target.Limit = *limit
		}
		if expiry != nil {
			target.ExpiresAt = *expiry
		}
		if err := a.Coordinator.Create(plan, &latest, target, latest.Keys); err != nil {
			return result, err
		}
		if err := a.Coordinator.DB.First(&job, "id = ?", id).Error; err != nil {
			return result, err
		}
	} else {
		var target quotaescrow.ControlTarget
		var plan quotaescrow.ControlPlan
		if json.Unmarshal([]byte(job.TargetJSON), &target) != nil || json.Unmarshal([]byte(job.PlanJSON), &plan) != nil || plan.Subscription != subscription || plan.Kind != kind || (limit != nil && *limit != target.Limit) || (expiry != nil && *expiry != target.ExpiresAt) {
			return result, errors.New("lifecycle idempotency key reused with different input")
		}
		if len(availability) > 1 || (len(availability) == 1 && ((availability[0].Disabled != nil && target.Disabled != *availability[0].Disabled) || (availability[0].Unlimited != nil && target.Unlimited != *availability[0].Unlimited))) {
			return result, errors.New("idempotency key reused with different availability")
		}
	}
	result = MeshOperationResult{Operation: id, Pending: !job.Complete}
	// Respond only after the local panel committed. Remote partitions are
	// visible as pending, never mistaken for a failed local reset to retry.
	var updates []quotaescrow.PolicyUpdate
	if err := json.Unmarshal([]byte(job.UpdatesJSON), &updates); err != nil {
		return result, err
	}
	if err := a.Local.ApplySharedUpdates(ctx, subscription, updates); err != nil {
		return result, err
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return result, nil
}

// TryMeshLifecycle is called only after the ordinary panel's authentication,
// authorization and CSRF middleware. The caller cannot choose keys/peer URLs.
func TryMeshLifecycle(ctx context.Context, email, kind, key string, limit, expiry *int64, availability ...MeshAvailability) (bool, MeshOperationResult, error) {
	var result MeshOperationResult
	var binding model.MeshBinding
	db := database.GetDB()
	if !db.Migrator().HasTable(&model.MeshBinding{}) {
		return false, result, nil
	}
	err := db.First(&binding, "email = ?", email).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, result, nil
	}
	if err != nil {
		return false, result, err
	}
	a := activeMeshAdministrator.Load()
	if a == nil {
		return true, result, errors.New("mesh lifecycle administrator is unavailable on this panel")
	}
	result, err = a.Queue(ctx, binding.Subscription, kind, key, limit, expiry, availability...)
	return true, result, err
}
