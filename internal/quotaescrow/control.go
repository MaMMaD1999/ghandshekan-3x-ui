package quotaescrow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// AliasClaim binds an administrator's request to the actual credential and
// local inbound associations, not merely to an email chosen by another master.
type AliasClaim struct {
	Email       string `json:"email"`
	Fingerprint string `json:"fingerprint"`
}

// ControlPlan is the immutable identity of a two-phase enrollment/transition.
// Timing is on the signed envelope so a retry may renew its authentication
// window without changing or abandoning a durable barrier.
type ControlPlan struct {
	ID              string                  `json:"id"`
	Subscription    string                  `json:"subscription"`
	Kind            string                  `json:"kind"`
	Epoch           string                  `json:"epoch"`
	NextEpoch       string                  `json:"nextEpoch"`
	Claims          map[string][]AliasClaim `json:"claims"`
	AccountingRoots []LegacyRoot            `json:"accountingRoots,omitempty"`
}

type ControlCommand struct {
	Plan       ControlPlan      `json:"plan"`
	Operation  string           `json:"operation"`
	Policy     *Policy          `json:"policy,omitempty"`
	Receipts   []ControlReceipt `json:"receipts,omitempty"`
	IssuedAt   int64            `json:"issuedAt"`
	ValidUntil int64            `json:"validUntil"`
}

type SignedControl struct {
	Command   ControlCommand `json:"command"`
	Signature []byte         `json:"signature"`
}

type ControlReceipt struct {
	PlanHash   string            `json:"planHash"`
	Owner      string            `json:"owner"`
	Local      map[string]int64  `json:"local"`
	Sources    map[string]string `json:"sources"`
	Freeze     *FreezeProof      `json:"freeze,omitempty"`
	Historical *LegacySnapshot   `json:"historical,omitempty"`
	Signature  []byte            `json:"signature"`
}

func ControlPlanHash(plan ControlPlan) string {
	b, _ := json.Marshal(plan)
	h := sha256.Sum256(append([]byte("ghandshekan/control-plan/v1\x00"), b...))
	return hex.EncodeToString(h[:])
}

func (p ControlPlan) Validate() error {
	if p.ID == "" || len(p.ID) > 128 || p.Subscription == "" || len(p.Subscription) > 512 || p.NextEpoch == "" || len(p.NextEpoch) > 128 || len(p.Epoch) > 128 || p.NextEpoch == p.Epoch || len(p.Claims) == 0 || len(p.Claims) > 256 {
		return errors.New("invalid control scope")
	}
	if (p.Kind == "enroll" && p.Epoch != "") || (p.Kind != "enroll" && p.Kind != "renew" && p.Kind != "reset") || (p.Kind != "enroll" && p.Epoch == "") {
		return errors.New("invalid lifecycle kind")
	}
	n := 0
	for owner, claims := range p.Claims {
		if owner == "" || len(owner) > 128 || len(claims) == 0 {
			return errors.New("empty control membership")
		}
		seen := map[string]bool{}
		for _, claim := range claims {
			fingerprint, err := hex.DecodeString(claim.Fingerprint)
			if claim.Email == "" || len(claim.Email) > 512 || seen[claim.Email] || err != nil || len(fingerprint) != 32 {
				return errors.New("invalid alias claim")
			}
			seen[claim.Email] = true
			n++
		}
	}
	if n > 100000 {
		return errors.New("too many aliases")
	}
	if len(p.AccountingRoots) != 0 {
		if p.Kind != "enroll" || len(p.AccountingRoots) > n {
			return errors.New("invalid historical roots")
		}
		seen := map[LegacyRoot]bool{}
		for _, root := range p.AccountingRoots {
			found := false
			for _, claim := range p.Claims[root.Owner] {
				found = found || claim.Email == root.Alias
			}
			if !found || seen[root] {
				return errors.New("historical root outside enrollment")
			}
			seen[root] = true
		}
	}
	return nil
}

func controlPayload(c ControlCommand) []byte {
	b, _ := json.Marshal(c)
	return append([]byte("ghandshekan/mesh-control/v1\x00"), b...)
}

func SignControl(c ControlCommand, key ed25519.PrivateKey) (SignedControl, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedControl{}, errors.New("invalid control signer")
	}
	if err := validateControl(c); err != nil {
		return SignedControl{}, err
	}
	c = clone(c)
	return SignedControl{Command: c, Signature: ed25519.Sign(key, controlPayload(c))}, nil
}

func validateControl(c ControlCommand) error {
	if err := c.Plan.Validate(); err != nil {
		return err
	}
	if c.IssuedAt <= 0 || c.ValidUntil <= c.IssuedAt || c.ValidUntil-c.IssuedAt > 900 {
		return errors.New("invalid control window")
	}
	switch c.Operation {
	case "prepare":
		if c.Policy != nil || len(c.Receipts) != 0 {
			return errors.New("prepare cannot carry commit data")
		}
	case "commit":
		if c.Policy == nil || c.Policy.Subscription != c.Plan.Subscription || c.Policy.Epoch != c.Plan.NextEpoch || len(c.Policy.Keys) != len(c.Plan.Claims) || len(c.Receipts) != len(c.Plan.Claims) {
			return errors.New("commit membership mismatch")
		}
		if _, err := New(*c.Policy); err != nil {
			return err
		}
		for owner := range c.Plan.Claims {
			if len(c.Policy.Keys[owner]) != ed25519.PublicKeySize {
				return errors.New("missing policy member")
			}
		}
		seenKeys := map[string]bool{}
		for _, key := range c.Policy.Keys {
			if seenKeys[string(key)] {
				return errors.New("members must have distinct usage keys")
			}
			seenKeys[string(key)] = true
		}
	default:
		return errors.New("unknown control operation")
	}
	return nil
}

func VerifyControl(s SignedControl, authority ed25519.PublicKey, owner string, now int64) (ControlCommand, error) {
	if len(authority) != ed25519.PublicKeySize || !ed25519.Verify(authority, controlPayload(s.Command), s.Signature) {
		return ControlCommand{}, errors.New("untrusted control command")
	}
	if err := validateControl(s.Command); err != nil {
		return ControlCommand{}, err
	}
	c := s.Command
	if now < c.IssuedAt || now >= c.ValidUntil || len(c.Plan.Claims[owner]) == 0 {
		return ControlCommand{}, errors.New("control command is stale or for another node")
	}
	if c.Policy != nil {
		for _, key := range c.Policy.Keys {
			if authority.Equal(ed25519.PublicKey(key)) {
				return ControlCommand{}, errors.New("control and usage keys must be separate")
			}
		}
	}
	return clone(c), nil
}

func receiptPayload(r ControlReceipt) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/control-receipt/v1\x00"), b...)
}

func SignControlReceipt(r ControlReceipt, key ed25519.PrivateKey) (ControlReceipt, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ControlReceipt{}, errors.New("invalid receipt signer")
	}
	r = clone(r)
	r.Signature = ed25519.Sign(key, receiptPayload(r))
	return r, nil
}

func VerifyControlReceipt(r ControlReceipt, p ControlPlan, key ed25519.PublicKey) error {
	claims := p.Claims[r.Owner]
	if r.PlanHash != ControlPlanHash(p) || len(claims) == 0 || len(r.Local) != len(claims) || len(r.Sources) != len(claims) || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, receiptPayload(r), r.Signature) {
		return errors.New("invalid prepared receipt")
	}
	for _, a := range claims {
		n, ok := r.Local[a.Email]
		if !ok || n < 0 || r.Sources[a.Email] == "" {
			return errors.New("invalid receipt baseline")
		}
	}
	if (p.Kind == "enroll") != (r.Freeze == nil) {
		return errors.New("receipt lifecycle mismatch")
	}
	if r.Historical != nil {
		if p.Kind != "enroll" || r.Historical.Owner != r.Owner || len(r.Historical.Aliases) != len(claims) {
			return errors.New("historical receipt scope mismatch")
		}
		for _, a := range claims {
			if _, ok := r.Historical.Aliases[a.Email]; !ok {
				return errors.New("historical receipt alias missing")
			}
		}
	}
	return nil
}
