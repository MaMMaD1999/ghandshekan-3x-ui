package quotaescrow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Inspection carries no administrator password or API token. Its authority
// signature authorizes only a short-lived, bounded, read-only inventory.
type Inspection struct {
	Owner      string   `json:"owner"`
	Nonce      string   `json:"nonce"`
	Emails     []string `json:"emails"`
	IssuedAt   int64    `json:"issuedAt"`
	ValidUntil int64    `json:"validUntil"`
}
type SignedInspection struct {
	Request   Inspection `json:"request"`
	Signature []byte     `json:"signature"`
}
type InspectedAlias struct {
	Claim        AliasClaim `json:"claim"`
	Local        bool       `json:"local"`
	Children     []string   `json:"children,omitempty"`
	Subscription string     `json:"subscription,omitempty"`
	Epoch        string     `json:"epoch,omitempty"`
	Pending      bool       `json:"pending,omitempty"`
	Limit        int64      `json:"limit"`
	ExpiresAt    int64      `json:"expiresAt"`
	Enabled      bool       `json:"enabled"`
}
type Inventory struct {
	Owner       string           `json:"owner"`
	RequestHash string           `json:"requestHash"`
	Aliases     []InspectedAlias `json:"aliases"`
	Signature   []byte           `json:"signature"`
}

func inspectionPayload(r Inspection) []byte {
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/mesh-inspection/v1\x00"), b...)
}
func InspectionHash(r Inspection) string {
	h := sha256.Sum256(inspectionPayload(r))
	return hex.EncodeToString(h[:])
}
func (r Inspection) validate() error {
	if r.Owner == "" || len(r.Owner) > 128 || len(r.Nonce) < 16 || len(r.Nonce) > 128 || len(r.Emails) == 0 || len(r.Emails) > 2000 || r.IssuedAt <= 0 || r.ValidUntil <= r.IssuedAt || r.ValidUntil-r.IssuedAt > 120 {
		return errors.New("invalid inspection scope/window")
	}
	seen := map[string]bool{}
	for _, email := range r.Emails {
		if email == "" || len(email) > 512 || seen[email] {
			return errors.New("invalid inspection alias")
		}
		seen[email] = true
	}
	return nil
}
func SignInspection(r Inspection, key ed25519.PrivateKey) (SignedInspection, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedInspection{}, errors.New("invalid inspection signer")
	}
	if err := r.validate(); err != nil {
		return SignedInspection{}, err
	}
	r = clone(r)
	return SignedInspection{Request: r, Signature: ed25519.Sign(key, inspectionPayload(r))}, nil
}
func VerifyInspection(r SignedInspection, authority ed25519.PublicKey, owner string, now int64) (Inspection, error) {
	if len(authority) != ed25519.PublicKeySize || !ed25519.Verify(authority, inspectionPayload(r.Request), r.Signature) {
		return Inspection{}, errors.New("untrusted inspection")
	}
	if err := r.Request.validate(); err != nil {
		return Inspection{}, err
	}
	if r.Request.Owner != owner || now < r.Request.IssuedAt || now >= r.Request.ValidUntil {
		return Inspection{}, errors.New("stale or misdirected inspection")
	}
	return clone(r.Request), nil
}
func inventoryPayload(r Inventory) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("ghandshekan/mesh-inventory/v1\x00"), b...)
}
func SignInventory(r Inventory, key ed25519.PrivateKey) (Inventory, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Inventory{}, errors.New("invalid inventory signer")
	}
	r = clone(r)
	r.Signature = ed25519.Sign(key, inventoryPayload(r))
	return r, nil
}
func VerifyInventory(r Inventory, request Inspection, key ed25519.PublicKey) error {
	if err := request.validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, inventoryPayload(r), r.Signature) || r.Owner != request.Owner || r.RequestHash != InspectionHash(request) || len(r.Aliases) != len(request.Emails) {
		return errors.New("untrusted inventory response")
	}
	for i, alias := range r.Aliases {
		h, err := hex.DecodeString(alias.Claim.Fingerprint)
		if alias.Claim.Email != request.Emails[i] || err != nil || len(h) != 32 || alias.Limit < 0 {
			return errors.New("invalid inventory alias")
		}
	}
	return nil
}
