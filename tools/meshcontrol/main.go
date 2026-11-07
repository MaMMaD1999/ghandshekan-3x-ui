// meshcontrol is an operator-only tool. It never reads a public panel password
// or accepts a peer address from the browser. Its journal is separate from the
// running panel DB; all member changes pass through authenticated control APIs.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type request struct {
	Subscription string                    `json:"subscription"`
	Roots        []quotaescrow.LegacyRoot  `json:"roots,omitempty"`
	Previous     string                    `json:"previous,omitempty"`
	Target       quotaescrow.ControlTarget `json:"target"`
}

func readPrivate(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 4<<20 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return errors.New("private bounded regular input required")
	}
	d := json.NewDecoder(io.LimitReader(f, (4<<20)+1))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid private input")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing private input")
	}
	return nil
}

func openJournal(path string) (*gorm.DB, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "?\r\n") {
		return nil, errors.New("absolute journal filename required")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() || (runtime.GOOS != "windows" && dir.Mode().Perm()&0077 != 0) {
		return nil, errors.New("journal parent directory must be private")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("journal must be private")
	}
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=10000&_journal_mode=WAL&_synchronous=FULL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&quotaescrow.ControlJob{}); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func run() error {
	configPath := flag.String("identity", "", "installed coordinator member identity")
	authorityPath := flag.String("authority", "", "private authority key file")
	journalPath := flag.String("journal", "", "separate durable operator journal")
	action := flag.String("action", "status", "plan-enroll, enroll, renew, reset, resume, watch or status")
	requestPath := flag.String("request", "", "private JSON subscription request")
	id := flag.String("operation", "", "durable operation ID for resume/status")
	deadline := flag.Duration("timeout", 2*time.Minute, "bounded operation timeout")
	flag.Parse()
	if *deadline <= 0 || *deadline > 30*time.Minute {
		return errors.New("timeout must be within 30 minutes")
	}
	if !slicesContains([]string{"plan-enroll", "enroll", "renew", "reset", "resume", "watch", "status"}, *action) {
		return errors.New("unknown action")
	}
	db, err := openJournal(*journalPath)
	if err != nil {
		return err
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	if *action == "status" {
		var job quotaescrow.ControlJob
		if err := db.First(&job, "id = ?", *id).Error; err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			Operation string `json:"operation"`
			Complete  bool   `json:"complete"`
			Revision  uint64 `json:"revision"`
		}{job.ID, job.Complete, job.Revision})
	}
	config, trust, err := service.LoadMeshConfig(*configPath)
	if err != nil {
		return err
	}
	var secret struct {
		PrivateKey []byte `json:"privateKey"`
	}
	if err := readPrivate(*authorityPath, &secret); err != nil {
		return err
	}
	key := ed25519.PrivateKey(secret.PrivateKey)
	if len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(config.Authority)) {
		return errors.New("authority does not match provisioned trust")
	}
	client, _, err := quotaescrow.HTTPClients(trust, "")
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	transport := quotaescrow.ControlClient{HTTP: client, Peers: config.Peers, Keys: config.PeerKeys}
	builder := quotaescrow.PlanBuilder{Authority: key, Keys: config.PeerKeys, Inspect: transport.Inspect}
	c := quotaescrow.Coordinator{Owner: config.Owner, DB: db, Authority: key, Call: transport.Execute, CheckReady: builder.CheckReady, UpdatePolicy: transport.UpdatePolicy}
	if config.ControlEpoch != "" {
		c.ControlEpoch, c.ControlKeys = config.ControlEpoch, config.PeerKeys
		wire := &meshconsensus.Wire{Owner: config.Owner, Epoch: config.ControlEpoch, Key: ed25519.PrivateKey(config.PrivateKey), Keys: config.PeerKeys, Peers: config.Peers, Direct: client}
		c.RegisterPolicy = func(ctx context.Context, p quotaescrow.Policy) error {
			r, err := meshconsensus.SignRegistration(p, key)
			if err != nil {
				return err
			}
			var out meshconsensus.Result
			if err := wire.Call(ctx, config.Owner, "submit", meshconsensus.Command{ID: "enroll-" + quotaescrow.PolicyHash(p), Registration: &r}, &out); err != nil {
				return err
			}
			if out.Error != "" {
				return errors.New(out.Error)
			}
			return nil
		}
	}
	if *action == "watch" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		cursor := ""
		// Resumes durable operations only. Creating new operations remains an
		// explicit authenticated action. An unreachable node never discards a job.
		for {
			next, results, err := c.RecoverPending(ctx, cursor, 8, min(*deadline, 2*time.Minute))
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return err
			}
			cursor = next
			for _, result := range results {
				if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
					return err
				}
			}
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	operation := *id
	if *action != "resume" {
		var input request
		if err := readPrivate(*requestPath, &input); err != nil {
			return err
		}
		if input.Target.Mode == "shared" {
			input.Target.Eventual = true
		}
		if input.Target.Eventual && config.ControlEpoch == "" {
			return errors.New("shared enrollment requires a provisioned majority control cluster")
		}
		var plan quotaescrow.ControlPlan
		var prior *quotaescrow.Policy
		if *action == "enroll" || *action == "plan-enroll" {
			if input.Previous != "" {
				return errors.New("enrollment cannot replace a prior policy")
			}
			var weights map[string]int64
			plan, weights, err = builder.Enrollment(ctx, input.Subscription, input.Roots)
			if err != nil {
				return err
			}
			if input.Target.Weights == nil {
				input.Target.Weights = weights
			}
		} else {
			if len(input.Roots) != 0 {
				return errors.New("transition must retain old membership")
			}
			var old quotaescrow.ControlJob
			if err := db.First(&old, "id = ?", input.Previous).Error; err != nil {
				return errors.New("completed previous operation required")
			}
			var previous quotaescrow.ControlPlan
			var policy quotaescrow.Policy
			if json.Unmarshal([]byte(old.PlanJSON), &previous) != nil || json.Unmarshal([]byte(old.PolicyJSON), &policy) != nil {
				return errors.New("invalid previous operation")
			}
			if !old.Complete && (policy.Version < 2) {
				return errors.New("initial enrollment/strict transition must finish before lifecycle updates")
			}
			if input.Subscription != policy.Subscription {
				return errors.New("previous subscription mismatch")
			}
			plan, err = builder.Transition(ctx, *action, previous, policy)
			if err != nil {
				return err
			}
			prior = &policy
		}
		keys := map[string][]byte{}
		for owner := range plan.Claims {
			keys[owner] = config.PeerKeys[owner]
		}
		if *action == "plan-enroll" {
			// Fingerprints/topology only; redirect this output to a private review file.
			return json.NewEncoder(os.Stdout).Encode(struct {
				Plan   quotaescrow.ControlPlan   `json:"plan"`
				Target quotaescrow.ControlTarget `json:"target"`
			}{plan, input.Target})
		}
		if err := c.Create(plan, prior, input.Target, keys); err != nil {
			return err
		}
		operation = plan.ID
		// Report the durable identifier BEFORE attempting any remote mutation.
		fmt.Fprintln(os.Stdout, "Operation:", operation)
	}
	_, done, err := c.Resume(ctx, operation)
	if err != nil {
		return fmt.Errorf("operation %s remains pending: %w", operation, err)
	}
	if !done {
		return errors.New("operation not complete")
	}
	fmt.Fprintln(os.Stdout, "Operation completed:", operation)
	return nil
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Mesh control:", err)
		os.Exit(1)
	}
}
