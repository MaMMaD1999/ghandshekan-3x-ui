package meshconsensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

const WirePath = "/mesh-consensus"
const maxPacketBytes = 96 << 20 // Includes base64 for a bounded Raft snapshot.

type packet struct {
	Epoch     string          `json:"epoch"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Nonce     string          `json:"nonce"`
	Kind      string          `json:"kind"`
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}
type routed struct {
	Packet  packet   `json:"packet"`
	Visited []string `json:"visited"`
}
type reply struct {
	Request   string          `json:"request"`
	Body      json.RawMessage `json:"body,omitempty"`
	Error     string          `json:"error,omitempty"`
	Signature []byte          `json:"signature"`
}

func packetPayload(p packet) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("ghandshekan/consensus-rpc/v1\x00"), b...)
}
func replyPayload(r reply) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/consensus-reply/v1\x00"), b...)
}

// Wire never resolves peer URLs from a request. Relays forward the original
// signed packet and return the destination's signature, not their own success.
type Wire struct {
	Owner, Epoch                        string
	Key                                 ed25519.PrivateKey
	Keys                                map[string][]byte
	Peers                               map[string]string
	Direct                              *http.Client
	Egress                              func() (*http.Client, error)
	handlerMu                           sync.RWMutex
	handle                              func(context.Context, string, string, json.RawMessage) (any, error)
	AttemptTimeout                      time.Duration
	slotsOnce                           sync.Once
	rpcSlots, adminSlots, snapshotSlots chan struct{}
}

func (w *Wire) SetHandler(handle func(context.Context, string, string, json.RawMessage) (any, error)) {
	w.handlerMu.Lock()
	defer w.handlerMu.Unlock()
	w.handle = handle
}
func (w *Wire) verify(p packet) error {
	if p.Epoch != w.Epoch || len(w.Keys[p.From]) != ed25519.PublicKeySize || len(w.Keys[p.To]) != ed25519.PublicKeySize || len(p.Nonce) < 16 || len(p.Nonce) > 128 || len(p.Kind) > 32 || !ed25519.Verify(w.Keys[p.From], packetPayload(p), p.Signature) {
		return errors.New("untrusted consensus packet")
	}
	switch p.Kind {
	case "append", "vote", "prevote", "snapshot", "timeout", "propose", "submit", "attest", "admit":
		return nil
	default:
		return errors.New("invalid consensus RPC")
	}
}
func (w *Wire) verifiedReply(p packet, r reply) error {
	if r.Request != digest(p) || !ed25519.Verify(w.Keys[p.To], replyPayload(r), r.Signature) {
		return errors.New("untrusted consensus reply")
	}
	return nil
}
func decodeBounded(r io.Reader, out any, limit int64) error {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > limit {
		return errors.New("consensus payload too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid consensus payload")
	}
	return nil
}
func (w *Wire) post(ctx context.Context, peer string, r routed, client *http.Client) (reply, error) {
	var out reply
	u, err := url.Parse(w.Peers[peer])
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/exchange" || client == nil || len(w.Keys[peer]) != ed25519.PublicKeySize {
		return out, errors.New("unprovisioned control route")
	}
	u.Path = WirePath
	body, err := json.Marshal(r)
	if err != nil {
		return out, err
	}
	if len(body) > maxPacketBytes {
		return out, errors.New("consensus payload too large")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mesh-RPC", r.Packet.Kind)
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("control redirects are forbidden") }
	response, err := c.Do(req)
	if err != nil {
		return out, errors.New("consensus peer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return out, errors.New("consensus peer rejected request")
	}
	if err := decodeBounded(response.Body, &out, maxPacketBytes); err != nil {
		return out, err
	}
	return out, w.verifiedReply(r.Packet, out)
}

func (w *Wire) attempt(ctx context.Context, peer string, r routed, client *http.Client) (reply, error) {
	timeout := w.AttemptTimeout
	if timeout == 0 {
		timeout = 1500 * time.Millisecond
	}
	if r.Packet.Kind == "snapshot" {
		timeout = 30 * time.Second
	}
	child, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return w.post(child, peer, r, client)
}

func (w *Wire) route(ctx context.Context, r routed, egress bool) (reply, error) {
	if out, err := w.attempt(ctx, r.Packet.To, r, w.Direct); err == nil {
		return out, nil
	}
	// A bounded relay path and deadline avoid forwarding loops and storms.
	// At most two relay candidates are attempted concurrently per hop.
	if len(r.Visited) < 4 {
		relayCtx, stopRelays := context.WithTimeout(ctx, 3500*time.Millisecond)
		defer stopRelays()
		ids := make([]string, 0, len(w.Peers))
		for id := range w.Peers {
			if id != r.Packet.To && !slices.Contains(r.Visited, id) {
				ids = append(ids, id)
			}
		}
		slices.Sort(ids)
		// Try pairs rather than only the first two: every provisioned bridge is usable.
		for start := 0; start < len(ids) && relayCtx.Err() == nil; start += 2 {
			child, cancel := context.WithCancel(relayCtx)
			type result struct {
				r   reply
				err error
			}
			results := make(chan result, 2)
			count := min(2, len(ids)-start)
			for _, id := range ids[start : start+count] {
				go func(id string) { v, e := w.post(child, id, r, w.Direct); results <- result{v, e} }(id)
			}
			for range count {
				v := <-results
				if v.err == nil {
					cancel()
					return v.r, nil
				}
			}
			cancel()
		}
	}
	// Only the originating member uses its explicitly configured accounting
	// outbound, and only after its direct and peer-relay attempts failed.
	if egress && ctx.Err() == nil && w.Egress != nil {
		client, err := w.Egress()
		if err == nil && client != nil {
			defer client.CloseIdleConnections()
			return w.attempt(ctx, r.Packet.To, r, client)
		}
	}
	return reply{}, errors.New("direct, mesh relay and accounting fallback are unavailable")
}

func (w *Wire) Call(ctx context.Context, to, kind string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	p := packet{Epoch: w.Epoch, From: w.Owner, To: to, Nonce: rand.Text(), Kind: kind, Body: b}
	if len(w.Key) != ed25519.PrivateKeySize {
		return errors.New("control identity unavailable")
	}
	p.Signature = ed25519.Sign(w.Key, packetPayload(p))
	if err := w.verify(p); err != nil {
		return err
	}
	r, err := w.route(ctx, routed{Packet: p, Visited: []string{w.Owner}}, true)
	if err != nil {
		return err
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	return json.Unmarshal(r.Body, out)
}

func (w *Wire) ServeHTTP(dst http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
		http.Error(dst, "authenticated peers only", http.StatusForbidden)
		return
	}
	w.slotsOnce.Do(func() {
		w.rpcSlots = make(chan struct{}, 32)
		w.adminSlots = make(chan struct{}, 8)
		w.snapshotSlots = make(chan struct{}, 2)
	})
	kind := req.Header.Get("X-Mesh-RPC")
	deadline := time.Now().Add(15 * time.Second)
	if kind == "snapshot" {
		deadline = time.Now().Add(60 * time.Second)
	}
	responseControl := http.NewResponseController(dst)
	_ = responseControl.SetReadDeadline(deadline)
	_ = responseControl.SetWriteDeadline(deadline)
	limit := int64(4 << 20)
	slots := w.rpcSlots
	if kind == "snapshot" {
		limit = maxPacketBytes
		slots = w.snapshotSlots
	} else if kind == "propose" || kind == "submit" {
		slots = w.adminSlots
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		http.Error(dst, "consensus busy", http.StatusServiceUnavailable)
		return
	}
	var r routed
	if err := decodeBounded(req.Body, &r, limit); err != nil {
		http.Error(dst, "invalid packet", http.StatusBadRequest)
		return
	}
	if kind != r.Packet.Kind || w.verify(r.Packet) != nil || len(r.Visited) == 0 || len(r.Visited) > 4 || r.Visited[0] != r.Packet.From {
		http.Error(dst, "invalid signature or route", http.StatusForbidden)
		return
	}
	seen := map[string]bool{}
	for _, id := range r.Visited {
		if seen[id] || len(w.Keys[id]) == 0 {
			http.Error(dst, "invalid relay path", http.StatusForbidden)
			return
		}
		seen[id] = true
	}
	if seen[w.Owner] && r.Packet.To != w.Owner {
		http.Error(dst, "relay loop", http.StatusConflict)
		return
	}
	timeout := 8 * time.Second
	if kind == "snapshot" {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	var out reply
	if r.Packet.To != w.Owner {
		if len(r.Visited) >= 4 {
			http.Error(dst, "relay limit", http.StatusServiceUnavailable)
			return
		}
		r.Visited = append(r.Visited, w.Owner)
		var err error
		out, err = w.route(ctx, r, false)
		if err != nil {
			http.Error(dst, "relay unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		var value any
		var err error
		w.handlerMu.RLock()
		handle := w.handle
		w.handlerMu.RUnlock()
		if handle == nil {
			err = errors.New("consensus is starting")
		} else {
			value, err = handle(ctx, r.Packet.From, r.Packet.Kind, r.Packet.Body)
		}
		out.Request = digest(r.Packet)
		if err != nil {
			out.Error = err.Error()
		} else {
			out.Body, err = json.Marshal(value)
			if err != nil {
				out.Error = "invalid consensus reply"
			}
		}
		out.Signature = ed25519.Sign(w.Key, replyPayload(out))
	}
	dst.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(dst).Encode(out)
}
