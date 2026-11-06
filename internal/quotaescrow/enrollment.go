package quotaescrow

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

// Enrollment is issued by a separately pinned control-plane authority. A peer's
// usage-signing key is not authority to enroll clients or mint another policy.
type Enrollment struct {
	Policy     Policy              `json:"policy"`
	Aliases    map[string][]string `json:"aliases"`
	IssuedAt   int64               `json:"issuedAt"`
	ValidUntil int64               `json:"validUntil"`
}

type SignedEnrollment struct {
	Enrollment Enrollment `json:"enrollment"`
	Signature  []byte     `json:"signature"`
}

func enrollmentPayload(e Enrollment) []byte {
	b, _ := json.Marshal(e)
	return append([]byte("ghandshekan/mesh-enrollment/v1\x00"), b...)
}

func SignEnrollment(e Enrollment, authority ed25519.PrivateKey) (SignedEnrollment, error) {
	if len(authority) != ed25519.PrivateKeySize {
		return SignedEnrollment{}, errors.New("invalid enrollment signer")
	}
	if err := validateEnrollment(e); err != nil {
		return SignedEnrollment{}, err
	}
	copy := clone(e)
	return SignedEnrollment{Enrollment: copy, Signature: ed25519.Sign(authority, enrollmentPayload(copy))}, nil
}

func validateEnrollment(e Enrollment) error {
	if _, err := New(e.Policy); err != nil {
		return err
	}
	if e.IssuedAt <= 0 || e.ValidUntil <= e.IssuedAt || e.ValidUntil-e.IssuedAt > 900 {
		return errors.New("invalid enrollment window")
	}
	if len(e.Aliases) != len(e.Policy.Keys) || len(e.Aliases) > 256 {
		return errors.New("enrollment membership mismatch")
	}
	keys := map[string]bool{}
	totalAliases := 0
	for owner, key := range e.Policy.Keys {
		aliases := e.Aliases[owner]
		if len(key) != ed25519.PublicKeySize || len(aliases) == 0 || len(aliases) > 100000 {
			return errors.New("invalid enrolled owner")
		}
		if keys[string(key)] {
			return errors.New("nodes must have distinct signing keys")
		}
		keys[string(key)] = true
		totalAliases += len(aliases)
		if totalAliases > 100000 {
			return errors.New("enrollment exceeds alias limit")
		}
		seen := map[string]bool{}
		for _, email := range aliases {
			if email == "" || len(email) > 512 || seen[email] {
				return errors.New("invalid enrollment alias")
			}
			seen[email] = true
		}
	}
	return nil
}

// VerifyEnrollment authenticates the whole policy AND alias mapping. The caller
// still must verify aliases against local authoritative clients and fence/drain
// them before Activate. Store.Activate rejects replay over an existing epoch.
func VerifyEnrollment(s SignedEnrollment, authority ed25519.PublicKey, owner string, localKey ed25519.PublicKey, now int64) (Policy, []string, error) {
	var empty Policy
	if len(authority) != ed25519.PublicKeySize || !ed25519.Verify(authority, enrollmentPayload(s.Enrollment), s.Signature) {
		return empty, nil, errors.New("untrusted enrollment")
	}
	e := s.Enrollment
	if err := validateEnrollment(e); err != nil {
		return empty, nil, err
	}
	for _, key := range e.Policy.Keys {
		if bytes.Equal(authority, key) {
			return empty, nil, errors.New("usage signer cannot be the enrollment authority")
		}
	}
	if now < e.IssuedAt || now >= e.ValidUntil {
		return empty, nil, errors.New("enrollment window elapsed or not started")
	}
	if len(localKey) != ed25519.PublicKeySize || !bytes.Equal(localKey, e.Policy.Keys[owner]) {
		return empty, nil, errors.New("enrollment is not for this node identity")
	}
	return clone(e.Policy), clone(e.Aliases[owner]), nil
}
