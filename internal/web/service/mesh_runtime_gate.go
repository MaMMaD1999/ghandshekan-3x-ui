package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var meshGuardEnabled atomic.Bool
var meshAdmissionReady atomic.Bool
var meshRestoreFault atomic.Bool

// Protected by the core lifecycle lock. A changed deny set must also reconcile
// credentials filtered out during a previous config reload or cold start.
var meshLastDenied []string

// BeginMeshRuntime runs before any production core start. A missing/invalid
// identity leaves enrolled clients fenced, while legacy clients remain usable.
func BeginMeshRuntime() {
	meshGuardEnabled.Store(true)
	meshAdmissionReady.Store(false)
	meshRestoreFault.Store(false)
	if err := preflightMeshCheckpoint(); err != nil {
		meshRestoreFault.Store(true)
	}
}

// Before any core start, detect restored aliases even if the restored panel DB
// predates enrollment entirely. A DB-only rollback cannot reopen those users.
func preflightMeshCheckpoint() error {
	c, _, err := LoadMeshConfig(MeshConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cp, err := OpenMeshCheckpoint(database.GetDB(), c, false)
	if err != nil {
		return err
	}
	return cp.Close()
}
func meshCanAdmit() bool {
	return !meshRestoreFault.Load() && (!meshGuardEnabled.Load() || meshAdmissionReady.Load())
}

// FenceMeshRuntime serializes core fences with configuration reloads. A new core
// starts without enrolled users and gains them only after this acknowledgement.
func (s *XrayService) FenceMeshRuntime(ctx context.Context, blocked []string) error {
	if meshRestoreFault.Load() {
		return ErrMeshRestore
	}
	changed, err := func() (bool, error) {
		lock.Lock()
		defer lock.Unlock()
		process := currentXrayProcess()
		if process == nil || !process.IsRunning() {
			meshAdmissionReady.Store(false)
			return false, nil
		}
		api := xray.XrayAPI{}
		if err := api.Init(process.GetAPIPort()); err != nil {
			return false, err
		}
		defer api.Close()
		if err := reconcileStartingMeshGate(ctx, &api, blocked, !meshAdmissionReady.Load()); err != nil {
			return false, err
		}
		denied := slices.Clone(blocked)
		slices.Sort(denied)
		changed := !slices.Equal(denied, meshLastDenied)
		meshLastDenied = denied
		return !meshAdmissionReady.Swap(true) || changed, nil
	}()
	if err != nil {
		return err
	}
	if changed {
		return s.RestartXray(false)
	}
	return nil
}

// OS process creation precedes the core's API listener. During this cold-start
// interval credentials are already fenced out of the generated config. Retry
// only then; loss of the API after admission must still trigger emergency stop.
func reconcileStartingMeshGate(ctx context.Context, api *xray.XrayAPI, blocked []string, cold bool) error {
	if !cold {
		return api.ReconcileUserGates(ctx, blocked)
	}
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err := api.ReconcileUserGates(startup, blocked)
		if status.Code(err) != codes.Unavailable {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return startup.Err()
		case <-timer.C:
		}
	}
}

func fenceMeshColdConfig(cfg *xray.Config) error {
	if !meshGuardEnabled.Load() {
		return nil
	}
	meshAdmissionReady.Store(false)
	var bindings []model.MeshBinding
	if err := database.GetDB().Find(&bindings).Error; err != nil {
		return err
	}
	if len(bindings) == 0 {
		return nil
	}
	blocked := map[string]bool{}
	for _, b := range bindings {
		blocked[b.Email] = true
	}
	for i := range cfg.InboundConfigs {
		inbound := &cfg.InboundConfigs[i]
		if len(inbound.Settings) == 0 {
			continue
		}
		var settings map[string]any
		if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
			return err
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(clients))
		for _, client := range clients {
			row, _ := client.(map[string]any)
			email, _ := row["email"].(string)
			if !blocked[email] {
				kept = append(kept, client)
			}
		}
		settings["clients"] = kept
		encoded, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		inbound.Settings = encoded
	}
	return nil
}

// SuspendMeshAdmission closes enrolled streams without disturbing legacy users.
// It must run before stopping the accounting workers, including panel-only
// restarts which deliberately keep the core process alive.
func (s *XrayService) SuspendMeshAdmission(ctx context.Context) error {
	lock.Lock()
	defer lock.Unlock()
	meshAdmissionReady.Store(false)
	var emails []string
	if err := database.GetDB().Model(&model.MeshBinding{}).Pluck("email", &emails).Error; err != nil {
		return err
	}
	if len(emails) == 0 {
		return nil
	}
	process := currentXrayProcess()
	if process == nil || !process.IsRunning() {
		return nil
	}
	api := xray.XrayAPI{}
	if err := api.Init(process.GetAPIPort()); err != nil {
		return err
	}
	defer api.Close()
	return api.ReconcileUserGates(ctx, emails)
}
