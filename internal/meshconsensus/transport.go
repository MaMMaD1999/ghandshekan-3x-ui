package meshconsensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Transport uses the same authenticated peer registry and ordered fallback
// routes as control requests. No public or arbitrary TCP proxy is introduced.
type Transport struct {
	Owner    string
	Call     func(context.Context, string, string, any, any) error
	consumer chan raft.RPC
	done     chan struct{}
	once     sync.Once
}

func NewTransport(owner string) *Transport {
	return &Transport{Owner: owner, consumer: make(chan raft.RPC, 32), done: make(chan struct{})}
}
func (t *Transport) Consumer() <-chan raft.RPC                                   { return t.consumer }
func (t *Transport) LocalAddr() raft.ServerAddress                               { return raft.ServerAddress(t.Owner) }
func (t *Transport) EncodePeer(id raft.ServerID, addr raft.ServerAddress) []byte { return []byte(id) }
func (t *Transport) DecodePeer(b []byte) raft.ServerAddress                      { return raft.ServerAddress(b) }
func (t *Transport) SetHeartbeatHandler(func(raft.RPC))                          {}
func (t *Transport) AppendEntriesPipeline(raft.ServerID, raft.ServerAddress) (raft.AppendPipeline, error) {
	return nil, raft.ErrPipelineReplicationNotSupported
}
func (t *Transport) Close() error { t.once.Do(func() { close(t.done) }); return nil }
func (t *Transport) call(id raft.ServerID, target raft.ServerAddress, kind string, in, out any) error {
	if string(id) != string(target) || t.Call == nil {
		return errors.New("invalid consensus peer")
	}
	timeout := 8 * time.Second
	if kind == "snapshot" {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.Call(ctx, string(id), kind, in, out)
}
func (t *Transport) AppendEntries(id raft.ServerID, target raft.ServerAddress, a *raft.AppendEntriesRequest, r *raft.AppendEntriesResponse) error {
	return t.call(id, target, "append", a, r)
}
func (t *Transport) RequestVote(id raft.ServerID, target raft.ServerAddress, a *raft.RequestVoteRequest, r *raft.RequestVoteResponse) error {
	return t.call(id, target, "vote", a, r)
}
func (t *Transport) RequestPreVote(id raft.ServerID, target raft.ServerAddress, a *raft.RequestPreVoteRequest, r *raft.RequestPreVoteResponse) error {
	return t.call(id, target, "prevote", a, r)
}
func (t *Transport) TimeoutNow(id raft.ServerID, target raft.ServerAddress, a *raft.TimeoutNowRequest, r *raft.TimeoutNowResponse) error {
	return t.call(id, target, "timeout", a, r)
}

type snapshotRPC struct {
	Request raft.InstallSnapshotRequest `json:"request"`
	Data    []byte                      `json:"data"`
}

func (t *Transport) InstallSnapshot(id raft.ServerID, target raft.ServerAddress, a *raft.InstallSnapshotRequest, r *raft.InstallSnapshotResponse, data io.Reader) error {
	if a.Size < 0 || a.Size > maxStateBytes {
		return errors.New("snapshot limit exceeded")
	}
	b, err := io.ReadAll(io.LimitReader(data, maxStateBytes+1))
	if err != nil {
		return err
	}
	if int64(len(b)) != a.Size {
		return errors.New("snapshot size mismatch")
	}
	return t.call(id, target, "snapshot", snapshotRPC{Request: *a, Data: b}, r)
}

func (t *Transport) Handle(ctx context.Context, from, kind string, body json.RawMessage) (any, error) {
	var command raft.WithRPCHeader
	var reader io.Reader
	switch kind {
	case "append":
		command = &raft.AppendEntriesRequest{}
	case "vote":
		command = &raft.RequestVoteRequest{}
	case "prevote":
		command = &raft.RequestPreVoteRequest{}
	case "timeout":
		command = &raft.TimeoutNowRequest{}
	case "snapshot":
		var s snapshotRPC
		if json.Unmarshal(body, &s) != nil || s.Request.Size < 0 || s.Request.Size > maxStateBytes || int64(len(s.Data)) != s.Request.Size {
			return nil, errors.New("invalid snapshot RPC")
		}
		command = &s.Request
		reader = bytes.NewReader(s.Data)
	default:
		return nil, errors.New("unknown consensus transport RPC")
	}
	if kind != "snapshot" && json.Unmarshal(body, command) != nil {
		return nil, errors.New("invalid consensus command")
	}
	h := command.GetRPCHeader()
	if string(h.ID) != from || string(h.Addr) != from {
		return nil, errors.New("Raft sender does not match authenticated peer")
	}
	if s, ok := command.(*raft.InstallSnapshotRequest); ok {
		// Membership changes are operator-controlled, not learned from snapshots.
		// Raft itself also verifies term and committed-log ordering.
		if s.LastLogIndex == 0 {
			return nil, errors.New("invalid snapshot log index")
		}
	}
	response := make(chan raft.RPCResponse, 1)
	select {
	case t.consumer <- raft.RPC{Command: command, Reader: reader, RespChan: response}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, errors.New("transport closed")
	}
	select {
	case r := <-response:
		return r.Response, r.Error
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, errors.New("transport closed")
	}
}
