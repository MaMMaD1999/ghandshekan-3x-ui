package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

const quorumSubscription = "mesh-control-canary-only-20261107"

func quorumCanary(c *service.MeshConfig, trust *tls.Config, action, authorityPath, operation, destination string, limit int64) error {
	if c.ControlEpoch != "canary-control-20261107" {
		return errors.New("refusing non-canary control generation")
	}
	direct, _, err := quotaescrow.HTTPClients(trust, "")
	if err != nil {
		return err
	}
	defer direct.CloseIdleConnections()
	wire := &meshconsensus.Wire{Owner: c.Owner, Epoch: c.ControlEpoch, Key: ed25519.PrivateKey(c.PrivateKey), Keys: c.PeerKeys, Peers: c.Peers, Direct: direct}
	if action == "quorum-serve" {
		tr := meshconsensus.NewTransport(c.Owner)
		tr.Call = wire.Call
		node, err := meshconsensus.Open(meshconsensus.Options{Owner: c.Owner, Epoch: c.ControlEpoch, Keys: c.PeerKeys, Key: ed25519.PrivateKey(c.PrivateKey), Authority: ed25519.PublicKey(c.Authority), Directory: filepath.Join(c.StateDir, "quorum"), Transport: tr, Bootstrap: true})
		if err != nil {
			return err
		}
		defer node.Close()
		defer tr.Close()
		node.Call = wire.Call
		wire.SetHandler(func(ctx context.Context, from, kind string, body json.RawMessage) (any, error) {
			if kind == "submit" || kind == "propose" || kind == "attest" || kind == "admit" {
				return node.Handle(ctx, kind, body)
			}
			return tr.Handle(ctx, from, kind, body)
		})
		server := &http.Server{Addr: c.Listen, TLSConfig: trust, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, Handler: wire}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		done := make(chan error, 1)
		go func() { done <- server.ListenAndServeTLS(c.CertFile, c.KeyFile) }()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = server.Shutdown(shutdown)
				cancel()
				return nil
			case err := <-done:
				return err
			case <-timer.C:
				p, err := node.FSM.Policy(quorumSubscription)
				_, leader := node.Raft.LeaderWithID()
				output := map[string]any{"owner": c.Owner, "leader": leader, "state": node.Raft.State().String(), "registered": err == nil, "version": p.Version, "generation": p.ResetGeneration, "limit": p.Limit}
				b, _ := json.Marshal(output)
				path := filepath.Join(c.StateDir, "quorum-status.json")
				if err := os.WriteFile(path+".tmp", b, 0600); err != nil {
					return err
				}
				if err := os.Rename(path+".tmp", path); err != nil {
					return err
				}
			}
		}
	}
	if destination == "" {
		destination = c.Owner
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	localPolicy := filepath.Join(c.StateDir, "quorum-client-policy.json")
	if action == "quorum-enroll" {
		st, err := os.Stat(authorityPath)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 4096 {
			return errors.New("private authority file required")
		}
		raw, err := os.ReadFile(authorityPath)
		if err != nil {
			return err
		}
		var key struct {
			PrivateKey []byte `json:"privateKey"`
		}
		if json.Unmarshal(raw, &key) != nil {
			return errors.New("invalid authority")
		}
		p := quotaescrow.Policy{Subscription: quorumSubscription, Epoch: "canary-lifetime", Mode: "shared", Limit: 10000, Version: 1, ResetGeneration: 1, Authority: c.Authority, Manager: c.Owner, Keys: c.PeerKeys, ControlEpoch: c.ControlEpoch, ControlKeys: c.PeerKeys, Grants: map[string]int64{}}
		for id := range c.PeerKeys {
			p.Grants[id] = 0
		}
		r, err := meshconsensus.SignRegistration(p, ed25519.PrivateKey(key.PrivateKey))
		if err != nil {
			return err
		}
		var out meshconsensus.Result
		if err := wire.Call(ctx, destination, "submit", meshconsensus.Command{ID: "canary-register", Registration: &r}, &out); err != nil {
			return err
		}
		if out.Error != "" {
			return errors.New(out.Error)
		}
		b, _ := json.Marshal(p)
		if err := os.WriteFile(localPolicy, b, 0600); err != nil {
			return err
		}
		fmt.Println("Canary registration committed by the majority.")
		return nil
	}
	kind := ""
	if action == "quorum-renew" {
		kind = "renew"
	}
	if action == "quorum-reset" {
		kind = "reset"
	}
	if kind == "" || operation == "" || limit < 0 {
		return errors.New("invalid canary change")
	}
	raw, err := os.ReadFile(localPolicy)
	if err != nil {
		return err
	}
	var previous quotaescrow.Policy
	if json.Unmarshal(raw, &previous) != nil {
		return errors.New("invalid canary client state")
	}
	var result meshconsensus.Result
	if err := wire.Call(ctx, destination, "submit", meshconsensus.Command{ID: operation, Subscription: quorumSubscription, Kind: kind, Patch: &meshconsensus.PolicyPatch{Limit: &limit}}, &result); err != nil {
		return err
	}
	if result.Error != "" || result.Update == nil {
		return errors.New("canary update was not committed")
	}
	u := *result.Update
	u.Votes = map[string][]byte{}
	for id := range c.PeerKeys {
		var vote []byte
		bounded, release := context.WithTimeout(ctx, 7*time.Second)
		err := wire.Call(bounded, id, "attest", u, &vote)
		release()
		if err == nil && quotaescrow.VerifyPolicyVote(u, c.PeerKeys[id], vote) {
			u.Votes[id] = vote
		}
		if len(u.Votes) > len(c.PeerKeys)/2 {
			break
		}
	}
	if err := quotaescrow.VerifyPolicyUpdate(previous, u); err != nil {
		return err
	}
	b, _ := json.Marshal(u.Next)
	if err := os.WriteFile(localPolicy, b, 0600); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": u.Next.Version, "generation": u.Next.ResetGeneration, "limit": u.Next.Limit, "verifiedVoters": len(u.Votes)})
}
