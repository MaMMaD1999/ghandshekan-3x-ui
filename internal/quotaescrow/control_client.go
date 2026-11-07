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
)

// ControlClient targets only the operator's provisioned HTTPS registry and
// verifies responses against pinned node usage keys. It cannot follow redirects
// or accept an endpoint/key supplied by the browser or by an inventory reply.
type ControlClient struct {
	HTTP  *http.Client
	Peers map[string]string
	Keys  map[string][]byte
}

func (c ControlClient) post(ctx context.Context, owner, path string, request, response any) error {
	if c.HTTP == nil || len(c.Keys[owner]) != ed25519.PublicKeySize {
		return errors.New("control peer is not provisioned")
	}
	u, err := url.Parse(c.Peers[owner])
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/exchange" {
		return errors.New("invalid private control endpoint")
	}
	u.Path = path
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(body) > 4<<20 {
		return errors.New("control request too large")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("control redirect refused") }
	r, err := client.Do(req)
	if err != nil {
		return errors.New("private control peer unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errors.New("private control request rejected")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("control response too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(response) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid control response")
	}
	return nil
}

func (c ControlClient) Inspect(ctx context.Context, owner string, request SignedInspection) (Inventory, error) {
	var out Inventory
	if request.Request.Owner != owner {
		return out, errors.New("inspection destination mismatch")
	}
	if err := c.post(ctx, owner, "/inspect", request, &out); err != nil {
		return Inventory{}, err
	}
	if err := VerifyInventory(out, request.Request, ed25519.PublicKey(c.Keys[owner])); err != nil {
		return Inventory{}, err
	}
	return out, nil
}

func (c ControlClient) Execute(ctx context.Context, owner string, request SignedControl) (ControlReceipt, error) {
	var out ControlReceipt
	if len(request.Command.Plan.Claims[owner]) == 0 {
		return out, errors.New("control destination mismatch")
	}
	if err := c.post(ctx, owner, "/control", request, &out); err != nil {
		return ControlReceipt{}, err
	}
	if out.Owner != owner {
		return ControlReceipt{}, errors.New("control response owner mismatch")
	}
	if err := VerifyControlReceipt(out, request.Command.Plan, ed25519.PublicKey(c.Keys[owner])); err != nil {
		return ControlReceipt{}, err
	}
	return out, nil
}
