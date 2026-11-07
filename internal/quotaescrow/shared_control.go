package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

type PolicyUpdateRequest struct {
	Subscription string         `json:"subscription"`
	Updates      []PolicyUpdate `json:"updates"`
}
type PolicyReceipt struct {
	Subscription string `json:"subscription"`
	Version      uint64 `json:"version"`
	PolicyHash   string `json:"policyHash"`
	Owner        string `json:"owner"`
	Signature    []byte `json:"signature"`
}

func policyReceiptPayload(r PolicyReceipt) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/shared-receipt/v1\x00"), b...)
}
func SignPolicyReceipt(p Policy, owner string, key ed25519.PrivateKey) (PolicyReceipt, error) {
	r := PolicyReceipt{Subscription: p.Subscription, Version: p.Version, PolicyHash: PolicyHash(p), Owner: owner}
	if p.Version == 0 || len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(p.Keys[owner])) {
		return r, errors.New("wrong policy receipt key")
	}
	r.Signature = ed25519.Sign(key, policyReceiptPayload(r))
	return r, nil
}
func VerifyPolicyReceipt(r PolicyReceipt, p Policy, owner string) error {
	if r.Subscription != p.Subscription || r.Version != p.Version || r.PolicyHash != PolicyHash(p) || r.Owner != owner || len(p.Keys[owner]) != ed25519.PublicKeySize || !ed25519.Verify(p.Keys[owner], policyReceiptPayload(r), r.Signature) {
		return errors.New("policy not acknowledged by destination")
	}
	return nil
}
func (c ControlClient) UpdatePolicy(ctx context.Context, owner string, request PolicyUpdateRequest) (PolicyReceipt, error) {
	var out PolicyReceipt
	if len(request.Updates) == 0 {
		return out, errors.New("policy certificates required")
	}
	p := request.Updates[len(request.Updates)-1].Next
	if p.Subscription != request.Subscription {
		return out, errors.New("policy scope mismatch")
	}
	if err := c.post(ctx, owner, "/policy", request, &out); err != nil {
		return PolicyReceipt{}, err
	}
	return out, VerifyPolicyReceipt(out, p, owner)
}
