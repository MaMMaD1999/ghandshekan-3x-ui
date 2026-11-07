// meshcanary exercises the production signed accounting transport across real
// hosts using a separate, explicitly named canary database and trust bundle.
// It does not import subscribers or change the host panel/runtime/firewall.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const subscription = "mesh-canary-acceptance-20261107"

type blockedTransport struct {
	base     http.RoundTripper
	endpoint string
}

func (t blockedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() == t.endpoint {
		return nil, errors.New("canary injected direct outage")
	}
	return t.base.RoundTrip(r)
}

func run() error {
	identity := flag.String("identity", "", "canary member identity")
	action := flag.String("action", "status", "init, serve, observe, sync, status")
	bytes := flag.Int64("bytes", 0, "local cumulative observed bytes")
	destination := flag.String("destination", "", "pinned destination ID")
	relays := flag.String("relays", "", "comma-separated pinned relay IDs")
	block := flag.Bool("block-direct", false, "inject direct outage in this canary client only")
	egress := flag.String("egress", "", "dedicated canary loopback accounting bridge")
	flag.Parse()
	c, trust, err := service.LoadMeshConfig(*identity)
	if err != nil {
		return err
	}
	if !strings.Contains(filepath.ToSlash(c.StateDir), "/mesh-canary-") {
		return errors.New("refusing a non-canary state directory")
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(c.StateDir, "canary.sqlite")
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=10000&_journal_mode=WAL&_synchronous=FULL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	if err := db.AutoMigrate(&quotaescrow.Record{}); err != nil {
		return err
	}
	s := quotaescrow.NewStore(db)
	if *action == "init" {
		grants := map[string]int64{}
		for owner := range c.PeerKeys {
			grants[owner] = 0
		}
		return s.Create(quotaescrow.Policy{Mode: "shared", Subscription: subscription, Epoch: "one", Limit: 10000, Grants: grants, Keys: c.PeerKeys})
	}
	direct, fallback, err := quotaescrow.HTTPClients(trust, *egress)
	if err != nil {
		return err
	}
	defer direct.CloseIdleConnections()
	if fallback != nil {
		defer fallback.CloseIdleConnections()
	}
	h := quotaescrow.HTTPExchange{Store: s, Owner: c.Owner, Key: ed25519.PrivateKey(c.PrivateKey), Subscription: subscription, Peers: c.Peers, Client: direct}
	switch *action {
	case "serve":
		server := &http.Server{Addr: c.Listen, TLSConfig: trust, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, Handler: h.Handler()}
		return server.ListenAndServeTLS(c.CertFile, c.KeyFile)
	case "observe":
		if err := s.Observe(subscription, c.Owner, c.PrivateKey, *bytes, time.Now().Unix()); err != nil {
			return err
		}
	case "sync":
		if *block {
			direct.Transport = blockedTransport{direct.Transport, c.Peers[*destination]}
		}
		l, err := s.Load(subscription)
		if err != nil {
			return err
		}
		transport := quotaescrow.SyncTransport{Direct: h.Attempt, Relay: h.Attempt}
		if fallback != nil {
			third := h
			third.Client = fallback
			transport.Egress = third.Attempt
		}
		var via []string
		if *relays != "" {
			via = strings.Split(*relays, ",")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		route, err := transport.Sync(ctx, *destination, via, l.Snapshot())
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "route:", route)
	case "status":
	default:
		return errors.New("unknown canary action")
	}
	l, err := s.Load(subscription)
	if err != nil {
		return err
	}
	used, err := l.Billed()
	if err != nil {
		return err
	}
	available, err := l.Available(c.Owner, time.Now().Unix())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Owner     string `json:"owner"`
		Billed    int64  `json:"billed"`
		Available int64  `json:"available"`
	}{c.Owner, used, available})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Mesh canary:", err)
		os.Exit(1)
	}
}
