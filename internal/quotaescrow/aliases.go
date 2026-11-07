package quotaescrow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
)

// AliasCatalog authorizes physical credentials/attachments, not spending.
// Fingerprints contain no usable credential. Revoked entries remain as
// tombstones so a delayed snapshot cannot resurrect a deleted device.
type AliasCatalog map[string]map[string]AliasAuthorization

type AliasAuthorization struct {
	Fingerprint string `json:"fingerprint"`
	Revision    uint64 `json:"revision"`
	Revoked     bool   `json:"revoked,omitempty"`
}

type AliasPatch struct {
	Owner            string `json:"owner"`
	Email            string `json:"email"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	Fingerprint      string `json:"fingerprint"`
	Revoked          bool   `json:"revoked,omitempty"`
}

// DeviceAuthorizationHash detects changes on ANY serving member, including a
// concurrently attached owner omitted by an older revoke request. Quota edits
// do not change it and therefore do not invalidate device-only operations.
func DeviceAuthorizationHash(p Policy, email string) string {
	owners := map[string]AliasAuthorization{}
	for owner, aliases := range p.Aliases {
		if a, ok := aliases[email]; ok {
			owners[owner] = a
		}
	}
	b, _ := json.Marshal([]any{p.Subscription, p.Epoch, email, owners})
	h := sha256.Sum256(append([]byte("ghandshekan/device-authorization/v1\x00"), b...))
	return hex.EncodeToString(h[:])
}

func validateAliasCatalog(p Policy) error {
	if p.Aliases == nil {
		return nil // Existing fixed-membership policies remain readable.
	}
	if p.ControlEpoch == "" || p.Version == 0 || len(p.Aliases) == 0 || len(p.Aliases) > len(p.Keys) {
		return errors.New("alias catalog requires a registered majority policy")
	}
	n := 0
	for owner, aliases := range p.Aliases {
		if _, ok := p.Keys[owner]; !ok || len(aliases) == 0 || len(aliases) > 2000 {
			return errors.New("alias catalog has an invalid owner or size")
		}
		for email, alias := range aliases {
			hash, err := hex.DecodeString(alias.Fingerprint)
			if email == "" || len(email) > 512 || strings.ContainsRune(email, '\x00') || err != nil || len(hash) != 32 || alias.Fingerprint != strings.ToLower(alias.Fingerprint) || alias.Revision == 0 || alias.Revision > p.Version {
				return errors.New("invalid alias authorization")
			}
			n++
		}
	}
	if n > 100000 {
		return errors.New("alias catalog too large")
	}
	return nil
}

// DraftAliasChange only changes one device's authorization. In particular it
// cannot reset usage, add quota, change expiry, or replace a metering identity.
// Runtime application MUST fence/drain before accepting the authorized local
// credential and preserve every pre-existing monotonic meter.
func DraftAliasChange(previous Policy, id string, patch AliasPatch) (PolicyUpdate, error) {
	return DraftAliasChanges(previous, id, []AliasPatch{patch})
}

// One logical device can have a physical alias on several traffic members.
// All of those grants commit together: a concurrent revoke must not be followed
// by a delayed half of an older attach operation enabling the device elsewhere.
func DraftAliasChanges(previous Policy, id string, patches []AliasPatch) (PolicyUpdate, error) {
	u := PolicyUpdate{ID: id, Kind: "alias", PreviousHash: PolicyHash(previous), Next: clone(previous)}
	if previous.Aliases == nil || previous.ControlEpoch == "" || previous.Version == math.MaxUint64 || len(patches) == 0 || len(patches) > 256 {
		return u, errors.New("policy does not support versioned alias membership")
	}
	u.Next.Version++
	seen := map[string]bool{}
	for _, patch := range patches {
		if patch.Email != patches[0].Email || patch.Revoked != patches[0].Revoked || seen[patch.Owner] {
			return u, errors.New("alias batch must change one device once per owner")
		}
		seen[patch.Owner] = true
		if _, ok := previous.Keys[patch.Owner]; !ok {
			return u, errors.New("alias owner is not an enrolled traffic member")
		}
		old, exists := previous.Aliases[patch.Owner][patch.Email]
		if old.Revision != patch.ExpectedRevision || old.Revision == math.MaxUint64 {
			return u, errors.New("alias changed; refresh before updating")
		}
		if (!exists && patch.Revoked) || (exists && old.Fingerprint == patch.Fingerprint && old.Revoked == patch.Revoked) {
			return u, errors.New("alias authorization is unchanged or absent")
		}
		if u.Next.Aliases[patch.Owner] == nil {
			u.Next.Aliases[patch.Owner] = map[string]AliasAuthorization{}
		}
		u.Next.Aliases[patch.Owner][patch.Email] = AliasAuthorization{Fingerprint: patch.Fingerprint, Revision: old.Revision + 1, Revoked: patch.Revoked}
	}
	return u, VerifyPolicyShape(previous, u)
}

// Consecutive commands change exactly one alias. A compact catch-up may cover
// several changes but can never drop tombstones or roll revisions backwards.
func verifyAliasAdvance(previous, next Policy, single bool) error {
	if previous.Aliases == nil || next.Aliases == nil || next.Version <= previous.Version {
		return errors.New("alias catalog cannot be implicitly enabled or removed")
	}
	steps := next.Version - previous.Version
	changes := 0
	revisions := map[string]uint64{}
	var device string
	var revoked bool
	for owner, aliases := range previous.Aliases {
		for email := range aliases {
			if _, ok := next.Aliases[owner][email]; !ok {
				return errors.New("alias authorization tombstone disappeared")
			}
		}
	}
	for owner, aliases := range next.Aliases {
		for email, alias := range aliases {
			old, exists := previous.Aliases[owner][email]
			if alias == old {
				continue
			}
			if alias.Revision <= old.Revision || alias.Revision-old.Revision > steps || (!exists && single && alias.Revoked) {
				return errors.New("alias revision regressed or skipped impossible changes")
			}
			if single && exists && alias.Fingerprint == old.Fingerprint && alias.Revoked == old.Revoked {
				return errors.New("alias revision advanced without a change")
			}
			changes++
			delta := alias.Revision - old.Revision
			if single {
				if changes == 1 {
					device, revoked = email, alias.Revoked
				}
				if email != device || alias.Revoked != revoked || delta != 1 {
					return errors.New("alias command changed multiple devices or revisions")
				}
			}
			revisions[email] = max(revisions[email], delta)
		}
	}
	if single && changes == 0 {
		return errors.New("an alias command must change a device authorization")
	}
	var total uint64
	for _, delta := range revisions {
		if delta > steps-total {
			return errors.New("more device changes than committed policy versions")
		}
		total += delta
	}
	if next.ResetGeneration >= previous.ResetGeneration && next.ResetGeneration-previous.ResetGeneration > steps-total {
		return errors.New("alias changes and resets exceed committed policy versions")
	}
	if !single && changes == 0 && !reflect.DeepEqual(previous.Aliases, next.Aliases) {
		return errors.New("alias catalog shape changed without authorization")
	}
	return nil
}
