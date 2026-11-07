package quotaescrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Exchange is end-to-end signed. A relay can deliver it but cannot acknowledge
// it on behalf of the destination or alter the subscription/accounting epoch.
// Transport authentication still restricts who may send these bounded messages.
type Exchange struct {
	Kind          string         `json:"kind"`
	From          string         `json:"from"`
	To            string         `json:"to"`
	Subscription  string         `json:"subscription"`
	Epoch         string         `json:"epoch"`
	Nonce         string         `json:"nonce"`
	Rows          []SignedRow    `json:"rows"`
	PolicyVersion uint64         `json:"policyVersion,omitempty"`
	Updates       []PolicyUpdate `json:"updates,omitempty"`
}
type SignedExchange struct {
	Message   Exchange `json:"message"`
	Signature []byte   `json:"signature"`
}

func exchangePayload(m Exchange) []byte {
	b, _ := json.Marshal(m)
	return append([]byte("ghandshekan/quota-exchange/v1\x00"), b...)
}

func signExchange(p Policy, owner string, key ed25519.PrivateKey, m Exchange) (SignedExchange, error) {
	if m.From != owner || len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(p.Keys[owner])) {
		return SignedExchange{}, errors.New("exchange key does not belong to owner")
	}
	m = clone(m)
	if err := validateExchange(p, m); err != nil {
		return SignedExchange{}, err
	}
	return SignedExchange{Message: m, Signature: ed25519.Sign(key, exchangePayload(m))}, nil
}

func validateExchange(p Policy, m Exchange) error {
	if m.Kind != "request" && m.Kind != "receipt" {
		return errors.New("invalid exchange kind")
	}
	if m.Subscription != p.Subscription || m.Epoch != p.Epoch {
		return ErrEpoch
	}
	if len(p.Keys[m.From]) != ed25519.PublicKeySize || len(p.Keys[m.To]) != ed25519.PublicKeySize || m.From == m.To {
		return errors.New("unknown or identical exchange peers")
	}
	nonce, err := hex.DecodeString(m.Nonce)
	if err != nil || len(nonce) != 32 || len(m.Rows) > len(p.Keys) {
		return errors.New("invalid exchange bounds")
	}
	// Verify certificates before accepting a newer generation of usage. The
	// persistent receiver separately checks exact replays against its history.
	for _, u := range m.Updates {
		if u.Next.Version <= p.Version {
			continue
		}
		if err := VerifyPolicyUpdate(p, u); err != nil {
			return err
		}
		p = u.Next
	}
	if m.PolicyVersion > p.Version {
		return errors.New("missing policy certificates")
	}
	// Validate cumulative rows before any persistent merge or acknowledgement.
	l, err := New(p)
	if err != nil {
		return err
	}
	return l.Merge(m.Rows)
}

func verifyExchange(p Policy, signed SignedExchange) error {
	if len(p.Keys[signed.Message.From]) != ed25519.PublicKeySize || !ed25519.Verify(p.Keys[signed.Message.From], exchangePayload(signed.Message), signed.Signature) {
		return errors.New("invalid exchange signature")
	}
	return validateExchange(p, signed.Message)
}

func NewExchange(p Policy, owner, destination string, key ed25519.PrivateKey, rows []SignedRow) (SignedExchange, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return SignedExchange{}, err
	}
	return signExchange(p, owner, key, Exchange{Kind: "request", From: owner, To: destination,
		Subscription: p.Subscription, Epoch: p.Epoch, Nonce: hex.EncodeToString(nonce), Rows: rows, PolicyVersion: p.Version})
}

// ReceiveExchange acknowledges ONLY after Store.Merge commits. A crash between
// commit and response is harmless: retrying the same cumulative rows is a no-op.
func (s *Store) ReceiveExchange(owner string, key ed25519.PrivateKey, request SignedExchange) (SignedExchange, error) {
	l, err := s.Load(request.Message.Subscription)
	if err != nil {
		return SignedExchange{}, err
	}
	if err = verifyExchange(l.policy, request); err != nil {
		return SignedExchange{}, err
	}
	m := request.Message
	if m.Kind != "request" || m.To != owner {
		return SignedExchange{}, errors.New("exchange addressed to another peer")
	}
	// Verify the local signer before modifying durable state.
	reply := Exchange{Kind: "receipt", From: owner, To: m.From, Subscription: m.Subscription, Epoch: m.Epoch, Nonce: m.Nonce}
	if _, err = signExchange(l.policy, owner, key, reply); err != nil {
		return SignedExchange{}, err
	}
	if err = s.Merge(m.Subscription, m.Rows); err != nil {
		return SignedExchange{}, err
	}
	l, err = s.Load(m.Subscription)
	if err != nil {
		return SignedExchange{}, err
	}
	reply.Rows = l.Snapshot()
	reply.PolicyVersion = l.policy.Version
	reply.Updates, err = s.PolicyUpdates(m.Subscription)
	if err != nil {
		return SignedExchange{}, err
	}
	return signExchange(l.policy, owner, key, reply)
}

// AcceptReceipt rejects stale receipts and forged relay ACKs. Persisting the
// destination snapshot is part of success, not background best-effort work.
func (s *Store) AcceptReceipt(request, receipt SignedExchange) error {
	l, err := s.Load(request.Message.Subscription)
	if err != nil {
		return err
	}
	if err = verifyExchange(l.policy, request); err != nil {
		return err
	}
	if err = verifyExchange(l.policy, receipt); err != nil {
		return err
	}
	if err := matchReceipt(request, receipt); err != nil {
		return err
	}
	return s.Merge(request.Message.Subscription, receipt.Message.Rows)
}

func matchReceipt(request, receipt SignedExchange) error {
	a, b := request.Message, receipt.Message
	if a.Kind != "request" || b.Kind != "receipt" || b.From != a.To || b.To != a.From || b.Nonce != a.Nonce || a.Subscription != b.Subscription || a.Epoch != b.Epoch {
		return errors.New("receipt does not acknowledge this destination and request")
	}
	return nil
}
