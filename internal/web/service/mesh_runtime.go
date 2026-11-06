package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

// MeshRuntime owns the private peer listener and both supervised workers. Its
// identity is installed by the operator, never returned through the panel API.
type MeshRuntime struct {
	cancel     context.CancelFunc
	done       chan struct{}
	server     *http.Server
	client     *http.Client
	xray       *XrayService
	enforcer   *MeshEnforcer
	checkpoint *MeshCheckpoint
	once       sync.Once
}

func MeshConfigPath() string {
	if path := os.Getenv("XUI_MESH_CONFIG"); path != "" {
		return path
	}
	return filepath.Join(config.GetDBFolderPath(), "mesh", "identity.json")
}

// StartMeshRuntime is called after the core start. Cold admission has already
// excluded managed aliases; a successful local fence acknowledgement admits
// only aliases whose committed allowance and expiry remain valid.
func StartMeshRuntime(parent context.Context, core *XrayService) (*MeshRuntime, error) {
	c, trust, err := LoadMeshConfig(MeshConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		var n int64
		if e := database.GetDB().Model(&model.MeshBinding{}).Count(&n).Error; e != nil {
			return nil, e
		}
		if n == 0 {
			return nil, nil
		}
		return nil, errors.New("enrolled clients have no installed mesh identity; admission remains closed")
	}
	if err != nil {
		return nil, err
	}
	settings := new(SettingService)
	owner, err := settings.GetPanelGuid()
	if err != nil {
		return nil, err
	}
	if owner != c.Owner {
		return nil, errors.New("mesh identity belongs to a different panel")
	}
	checkpoint, err := OpenMeshCheckpoint(database.GetDB(), c, false)
	if err != nil {
		meshRestoreFault.Store(true)
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			checkpoint.Close()
		}
	}()
	direct, _, err := quotaescrow.HTTPClients(trust, "")
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		direct.CloseIdleConnections()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r := &MeshRuntime{cancel: cancel, done: make(chan struct{}), client: direct, xray: core, checkpoint: checkpoint}
	worker := &MeshExchangeWorker{DB: database.GetDB(), Owner: c.Owner, Key: ed25519.PrivateKey(c.PrivateKey), Peers: c.Peers, Trust: trust, Direct: direct, AccountingProxy: settings.AccountingSyncProxyURL}
	check := func() error {
		if err := checkpoint.Advance(database.GetDB()); err != nil {
			meshRestoreFault.Store(true)
			return err
		}
		return nil
	}
	worker.Checkpoint = check
	r.enforcer = &MeshEnforcer{DB: database.GetDB(), Fence: core.FenceMeshRuntime, KeyForOwner: func(owner string) (ed25519.PrivateKey, error) {
		if owner != c.Owner {
			return nil, errors.New("foreign local meter owner")
		}
		return ed25519.PrivateKey(c.PrivateKey), nil
	}}
	r.enforcer.Checkpoint = check
	// Cap concurrent authenticated exchanges as well as payload sizes. No panel
	// login, bearer credential or unrestricted proxy endpoint is mounted here.
	capacity := make(chan struct{}, 16)
	handler := worker.Handler()
	r.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/exchange" {
			http.NotFound(w, req)
			return
		}
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, req)
	})}
	emergency := func(cause error) error {
		meshAdmissionReady.Store(false)
		logger.Error("mesh enforcement stopped: ", cause)
		return core.StopXray()
	}
	// Ordinary unreachable peers are expected. Rate-limit logs so a partition
	// does not fill disks or obscure local enforcement failures.
	var logMu sync.Mutex
	lastLog := map[string]time.Time{}
	supervisor := MeshSupervisor{Local: r.enforcer.ReconcileCurrent, Exchange: worker.Cycle, EmergencyStop: emergency, LocalInterval: time.Second, ExchangeInterval: 5 * time.Second, Report: func(kind string, e error) {
		logMu.Lock()
		defer logMu.Unlock()
		if time.Since(lastLog[kind]) < time.Minute {
			return
		}
		lastLog[kind] = time.Now()
		logger.Warningf("mesh %s: %v", kind, e)
	}}
	go func() {
		defer close(r.done)
		defer checkpoint.Close()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := r.server.Serve(tls.NewListener(listener, trust)); e != nil && !errors.Is(e, http.ErrServerClosed) && ctx.Err() == nil {
				_ = emergency(e)
				cancel()
			}
		}()
		_ = supervisor.Run(ctx)
		cancel()
		shutdown, release := context.WithTimeout(context.Background(), 5*time.Second)
		_ = r.server.Shutdown(shutdown)
		release()
		_ = listener.Close()
		wg.Wait()
		direct.CloseIdleConnections()
	}()
	started = true
	return r, nil
}

func (r *MeshRuntime) Stop() error {
	if r == nil {
		return nil
	}
	var result error
	r.once.Do(func() {
		// Cancel and wait for any in-flight admission cycle before the final
		// fence, so that cycle cannot undo the shutdown barrier afterwards.
		r.cancel()
		<-r.done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = r.xray.SuspendMeshAdmission(ctx)
		if result != nil {
			result = errors.Join(result, r.xray.StopXray())
		}
	})
	return result
}
