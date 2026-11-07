package quotaescrow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const maxExchangeBytes = 1 << 20

// HTTPExchange accepts only provisioned peer URLs. It never reads a destination
// URL from an incoming message, shares admin tokens, or follows redirects.
// A separate client may route fallback through the loopback accounting bridge.
type HTTPExchange struct {
	Store        *Store
	Owner        string
	Key          ed25519.PrivateKey
	Subscription string
	Peers        map[string]string
	Client       *http.Client
	// Checkpoint validates restores and durably records every locally published
	// transfer/receipt before it can authorize spending on another member.
	Checkpoint       func() error
	ScopedCheckpoint func(string) error
	ApplyUpdates     func(context.Context, string, []PolicyUpdate) error
}

func (h HTTPExchange) learn(ctx context.Context, signed SignedExchange) error {
	l, err := h.Store.Load(signed.Message.Subscription)
	if err != nil {
		return err
	}
	if err := verifyExchange(l.policy, signed); err != nil {
		return err
	}
	if len(signed.Message.Updates) == 0 {
		return nil
	}
	if h.ApplyUpdates == nil {
		return errors.New("shared lifecycle adapter unavailable")
	}
	return h.ApplyUpdates(ctx, signed.Message.Subscription, signed.Message.Updates)
}

func (h HTTPExchange) checkpoint(subscription string) error {
	if h.ScopedCheckpoint != nil {
		return h.ScopedCheckpoint(subscription)
	}
	if h.Checkpoint != nil {
		return h.Checkpoint()
	}
	return nil
}

func decodeExchange(reader io.Reader) (SignedExchange, error) {
	var result SignedExchange
	body, err := io.ReadAll(io.LimitReader(reader, maxExchangeBytes+1))
	if err != nil {
		return result, err
	}
	if len(body) > maxExchangeBytes {
		return result, errors.New("accounting exchange too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("trailing exchange data")
	}
	return result, nil
}

func (h HTTPExchange) post(ctx context.Context, peer string, request SignedExchange, relayed bool) (SignedExchange, error) {
	var empty SignedExchange
	address, ok := h.Peers[peer]
	if !ok {
		return empty, errors.New("peer is not provisioned")
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return empty, errors.New("peer requires an explicit HTTPS endpoint")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return empty, err
	}
	if len(body) > maxExchangeBytes {
		return empty, errors.New("accounting exchange too large")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return empty, err
	}
	req.Header.Set("Content-Type", "application/json")
	if relayed {
		req.Header.Set("X-Accounting-Relayed", "1")
	}
	client := http.Client{Timeout: 5 * time.Second}
	if h.Client != nil {
		client = *h.Client
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return empty, errors.New("accounting peer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, errors.New("accounting peer rejected exchange")
	}
	return decodeExchange(response.Body)
}

// Attempt implements SyncAttempt. A relay must return the actual destination's
// signed receipt; its own HTTP success is insufficient to advance sync state.
func (h HTTPExchange) Attempt(ctx context.Context, destination, via string, rows []SignedRow) error {
	if h.Store == nil {
		return errors.New("missing accounting store")
	}
	if err := h.checkpoint(h.Subscription); err != nil {
		return err
	}
	l, err := h.Store.Load(h.Subscription)
	if err != nil {
		return err
	}
	request, err := NewExchange(l.policy, h.Owner, destination, h.Key, rows)
	if err != nil {
		return err
	}
	if l.policy.Version > 0 {
		request.Message.Updates, err = h.Store.PolicyUpdates(h.Subscription)
		if err != nil {
			return err
		}
		request, err = signExchange(l.policy, h.Owner, h.Key, request.Message)
		if err != nil {
			return err
		}
	}
	if err := h.checkpoint(h.Subscription); err != nil {
		return err
	}
	receipt, err := h.post(ctx, via, request, false)
	if err != nil {
		return err
	}
	if err := matchReceipt(request, receipt); err != nil {
		return err
	}
	if err := h.learn(ctx, receipt); err != nil {
		return err
	}
	if err := h.Store.AcceptReceipt(request, receipt); err != nil {
		return err
	}
	return h.checkpoint(h.Subscription)
}

// Handler supports one authenticated intermediary. This is deliberately bounded:
// relays forward only to the final provisioned peer and never recurse/fan out.
// Mounting, peer provisioning and admission limits belong to the panel adapter.
func (h HTTPExchange) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if h.Store == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		request, err := decodeExchange(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		l, err := h.Store.Load(request.Message.Subscription)
		if err != nil || verifyExchange(l.policy, request) != nil || request.Message.Kind != "request" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := h.checkpoint(request.Message.Subscription); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if len(l.policy.Keys[h.Owner]) != ed25519.PublicKeySize || h.learn(r.Context(), request) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var receipt SignedExchange
		if request.Message.To == h.Owner {
			receipt, err = h.Store.ReceiveExchange(h.Owner, h.Key, request)
		} else {
			// Only members of this subscription can act as an intermediary.
			if len(l.policy.Keys[h.Owner]) != ed25519.PublicKeySize || r.Header.Get("X-Accounting-Relayed") != "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			receipt, err = h.post(ctx, request.Message.To, request, true)
			if err == nil {
				err = matchReceipt(request, receipt)
			}
			if err == nil {
				err = h.learn(ctx, receipt)
			}
			if err == nil {
				// Valid receipt also merges into the relay, keeping its view current.
				err = h.Store.AcceptReceipt(request, receipt)
			}
		}
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := h.checkpoint(request.Message.Subscription); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}
