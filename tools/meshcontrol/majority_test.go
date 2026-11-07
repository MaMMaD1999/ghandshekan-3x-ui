package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestMajorityOperatorLostReplyRetriesExactResetAfterNewerRenewal(t *testing.T) {
	pub, authority, _ := ed25519.GenerateKey(nil)
	keys := map[string][]byte{}
	for _, name := range []string{"master", "node-a", "node-b"} {
		key, _, _ := ed25519.GenerateKey(nil)
		keys[name] = key
	}
	fsm, err := meshconsensus.NewFSM("test-control", keys, pub)
	if err != nil {
		t.Fatal(err)
	}
	p := quotaescrow.Policy{Subscription: "subscriber", Epoch: "lifetime", Mode: "shared", Limit: 1000,
		Version: 1, ResetGeneration: 1, Manager: "master", Authority: pub, Keys: keys,
		ControlEpoch: "test-control", ControlKeys: keys, Grants: map[string]int64{"master": 0, "node-a": 0, "node-b": 0}}
	r, err := meshconsensus.SignRegistration(p, authority)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(c meshconsensus.Command) meshconsensus.Result {
		b, _ := json.Marshal(c)
		return fsm.Apply(&raft.Log{Data: b}).(meshconsensus.Result)
	}
	if result := apply(meshconsensus.Command{ID: "register", Registration: &r}); result.Error != "" {
		t.Fatal(result.Error)
	}
	input := request{Subscription: p.Subscription, Target: quotaescrow.ControlTarget{Mode: "shared", Limit: 2000}}
	command, err := majorityCommand("reset", "user-supplied-durable-id", input)
	if err != nil {
		t.Fatal(err)
	}
	lost := true
	call := func(_ context.Context, owner, kind string, in, out any) error {
		if owner != "node-a" || kind != "submit" {
			t.Fatal("operator bypassed the running member", owner, kind)
		}
		result := apply(in.(meshconsensus.Command))
		if lost {
			lost = false
			return errors.New("response lost after commit")
		}
		*out.(*meshconsensus.Result) = result
		return nil
	}
	var output bytes.Buffer
	if err := submitMajorityChange(context.Background(), "node-a", command, call, &output); err == nil || !strings.Contains(output.String(), command.ID) {
		t.Fatal("lost response was not resumable", err, output.String())
	}
	input.Target.Limit = 3000
	newer, _ := majorityCommand("renew", "later-renewal", input)
	if result := apply(newer); result.Error != "" {
		t.Fatal(result.Error)
	}
	output.Reset()
	if err := submitMajorityChange(context.Background(), "node-a", command, call, &output); err != nil {
		t.Fatal(err)
	}
	latest, err := fsm.Policy(p.Subscription)
	if err != nil || latest.Version != 3 || latest.ResetGeneration != 2 || latest.Limit != 3000 {
		t.Fatal("retry changed committed quota or reset twice", latest, err)
	}
	if !strings.Contains(output.String(), `"applicationPending":true`) || !strings.Contains(output.String(), `"version":2`) {
		t.Fatal("reply invented full convergence or lost original result", output.String())
	}
	changed, _ := majorityCommand("reset", "user-supplied-durable-id", input)
	if err := submitMajorityChange(context.Background(), "node-a", changed, call, &output); err == nil {
		t.Fatal("reused a reset ID with changed input")
	}
}

func TestMajorityOperatorRejectsAmbiguousInput(t *testing.T) {
	base := request{Subscription: "s", Target: quotaescrow.ControlTarget{Mode: "shared", Limit: 10}}
	for _, change := range []func(*request){
		func(r *request) { r.Previous = "coordinator-job" },
		func(r *request) { r.Roots = []quotaescrow.LegacyRoot{{Owner: "a", Alias: "b"}} },
		func(r *request) { r.Target.Weights = map[string]int64{} },
		func(r *request) { r.Target.ScheduledAt = 1 },
		func(r *request) { r.Target.Unlimited = true },
	} {
		input := base
		change(&input)
		if _, err := majorityCommand("reset", "stable-id", input); err == nil {
			t.Fatal("accepted unsupported target", input)
		}
	}
	if _, err := majorityCommand("reset", "", base); err == nil {
		t.Fatal("accepted a reset without a durable retry ID")
	}
}
