package quotaescrow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"
)

// PlanBuilder discovers only the independently provisioned member registry.
// The operator selects accounting roots, not credentials or guessed byte totals.
// Inspection is read-only: a missing member cannot fence a healthy subscription.
type PlanBuilder struct {
	Authority ed25519.PrivateKey
	Keys      map[string][]byte
	Inspect   func(context.Context, string, SignedInspection) (Inventory, error)
}

func controlNonce() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (b PlanBuilder) inventory(ctx context.Context, owner string, emails []string) (Inventory, error) {
	if b.Inspect == nil || len(b.Authority) != ed25519.PrivateKeySize || len(b.Keys[owner]) != ed25519.PublicKeySize {
		return Inventory{}, errors.New("member not independently provisioned")
	}
	now := time.Now().Unix()
	r, err := SignInspection(Inspection{Owner: owner, Emails: emails, Nonce: controlNonce(), IssuedAt: now - 1, ValidUntil: now + 119}, b.Authority)
	if err != nil {
		return Inventory{}, err
	}
	out, err := b.Inspect(ctx, owner, r)
	if err != nil {
		return Inventory{}, err
	}
	if err = VerifyInventory(out, r.Request, b.Keys[owner]); err != nil {
		return Inventory{}, err
	}
	return out, nil
}

// Enrollment builds a complete legacy accounting forest and rejects cycles or
// duplicate physical aliases before any prepare request. Device aliases can be
// separate roots of the same subscription; the target policy is explicit.
func (b PlanBuilder) Enrollment(ctx context.Context, subscription string, roots []LegacyRoot) (ControlPlan, map[string]int64, error) {
	p := ControlPlan{ID: controlNonce(), Subscription: subscription, Kind: "enroll", NextEpoch: controlNonce(), Claims: map[string][]AliasClaim{}, AccountingRoots: slices.Clone(roots)}
	weights := map[string]int64{}
	seen := map[LegacyRoot]bool{}
	queue := slices.Clone(roots)
	if len(queue) == 0 || len(queue) > 2000 {
		return ControlPlan{}, nil, errors.New("bounded accounting roots required")
	}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return ControlPlan{}, nil, err
		}
		root := queue[0]
		queue = queue[1:]
		if seen[root] || len(seen) >= 100000 {
			return ControlPlan{}, nil, errors.New("cyclic or multiply imported accounting alias")
		}
		seen[root] = true
		inventory, err := b.inventory(ctx, root.Owner, []string{root.Alias})
		if err != nil {
			return ControlPlan{}, nil, err
		}
		alias := inventory.Aliases[0]
		if alias.Pending || alias.Subscription != "" || alias.Epoch != "" {
			return ControlPlan{}, nil, errors.New("alias is already enrolled or transitioning")
		}
		if alias.ExpiresAt < 0 {
			return ControlPlan{}, nil, errors.New("activate first-use expiry before enrollment")
		}
		p.Claims[root.Owner] = append(p.Claims[root.Owner], alias.Claim)
		if alias.Local {
			weights[root.Owner] = 1
		} else if _, ok := weights[root.Owner]; !ok {
			weights[root.Owner] = 0
		}
		for _, child := range alias.Children {
			if len(b.Keys[child]) != ed25519.PublicKeySize {
				return ControlPlan{}, nil, errors.New("legacy child has no trusted mesh identity")
			}
			queue = append(queue, LegacyRoot{Owner: child, Alias: root.Alias})
		}
	}
	for owner := range p.Claims {
		slices.SortFunc(p.Claims[owner], func(a, z AliasClaim) int {
			if a.Email < z.Email {
				return -1
			}
			if a.Email > z.Email {
				return 1
			}
			return 0
		})
	}
	if err := p.Validate(); err != nil {
		return ControlPlan{}, nil, err
	}
	return p, weights, nil
}

// Transition uses the exact previous signed membership, not current panel
// association discovery. Losing a node or deleting an alias cannot silently
// remove its unreported consumption from reset/renewal.
func (b PlanBuilder) Transition(ctx context.Context, kind string, previous ControlPlan, prior Policy) (ControlPlan, error) {
	if kind != "reset" && kind != "renew" {
		return ControlPlan{}, errors.New("invalid transition")
	}
	if err := previous.Validate(); err != nil {
		return ControlPlan{}, err
	}
	if prior.Subscription != previous.Subscription || (prior.Epoch != previous.NextEpoch && (prior.Version == 0 || prior.Epoch != previous.Epoch)) || len(prior.Keys) != len(previous.Claims) {
		return ControlPlan{}, errors.New("previous membership mismatch")
	}
	p := ControlPlan{ID: controlNonce(), Subscription: prior.Subscription, Kind: kind, Epoch: prior.Epoch, NextEpoch: controlNonce(), Claims: map[string][]AliasClaim{}}
	for owner, claims := range previous.Claims {
		if !ed25519.PublicKey(prior.Keys[owner]).Equal(ed25519.PublicKey(b.Keys[owner])) {
			return ControlPlan{}, errors.New("member key changed")
		}
		if prior.Version > 0 {
			p.Claims[owner] = clone(claims)
			continue
		}
		emails := make([]string, len(claims))
		for i, claim := range claims {
			emails[i] = claim.Email
		}
		for start := 0; start < len(emails); start += 2000 {
			inventory, err := b.inventory(ctx, owner, emails[start:min(start+2000, len(emails))])
			if err != nil {
				return ControlPlan{}, err
			}
			for _, alias := range inventory.Aliases {
				if alias.Pending || alias.Subscription != prior.Subscription || alias.Epoch != prior.Epoch {
					return ControlPlan{}, errors.New("member is not in the previous committed epoch")
				}
				p.Claims[owner] = append(p.Claims[owner], alias.Claim)
			}
		}
	}
	return p, p.Validate()
}

// CheckReady is a best-effort preflight before the first durable barrier. It
// cannot promise a peer will remain reachable afterwards; recovery uses the
// immutable operation and signed receipts if a failure races with prepare.
func (b PlanBuilder) CheckReady(ctx context.Context, plan ControlPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	for owner, claims := range plan.Claims {
		for start := 0; start < len(claims); start += 2000 {
			batch := claims[start:min(start+2000, len(claims))]
			emails := make([]string, len(batch))
			for i, claim := range batch {
				emails[i] = claim.Email
			}
			inventory, err := b.inventory(ctx, owner, emails)
			if err != nil {
				return err
			}
			for i, alias := range inventory.Aliases {
				if alias.Pending || alias.Claim != batch[i] {
					return errors.New("membership changed since planning")
				}
				if plan.Kind == "enroll" {
					if alias.Subscription != "" || alias.Epoch != "" {
						return errors.New("alias enrolled since planning")
					}
				} else if alias.Subscription != plan.Subscription || alias.Epoch != plan.Epoch {
					return errors.New("member epoch changed since planning")
				}
			}
		}
	}
	return nil
}
