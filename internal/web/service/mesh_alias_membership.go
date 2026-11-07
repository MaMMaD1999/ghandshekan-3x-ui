package service

import (
	"crypto/rand"
	"errors"
	"slices"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func meshAliasAuthorized(p quotaescrow.Policy, b model.MeshBinding) bool {
	if p.Aliases == nil {
		return b.AuthorizationRevision == 0 && b.AuthorizationFingerprint == ""
	}
	a, ok := p.Aliases[b.Owner][b.Email]
	return ok && !a.Revoked && a.Revision == b.AuthorizationRevision && a.Fingerprint == b.AuthorizationFingerprint
}

// Called only inside the fenced, drained policy transaction. New aliases must
// have been provisioned disabled and must never have carried traffic. Historical
// aliases enter through enrollment's signed cutover, not this zero-byte path.
// Existing meters and watermarks are never overwritten, including revocation.
func bindAuthorizedMeshAliases(tx *gorm.DB, p quotaescrow.Policy, owner string) ([]string, error) {
	if p.Aliases == nil {
		return nil, errors.New("versioned alias catalog required")
	}
	var emails []string
	for email, authorization := range p.Aliases[owner] {
		var binding model.MeshBinding
		err := tx.First(&binding, "email = ?", email).Error
		fresh := errors.Is(err, gorm.ErrRecordNotFound)
		if err != nil && !fresh {
			return nil, err
		}
		if !fresh && (binding.Owner != owner || binding.Subscription != p.Subscription) {
			return nil, errors.New("alias is already owned by another subscription")
		}
		var client model.ClientRecord
		if err := tx.First(&client, "email = ?", email).Error; err != nil {
			return nil, errors.New("authorized alias has not been provisioned locally")
		}
		fingerprint, err := MeshAliasFingerprint(tx, email)
		if err != nil || fingerprint != authorization.Fingerprint {
			return nil, errors.New("local credential/attachments differ from alias authorization")
		}
		if fresh {
			if client.Enable {
				return nil, errors.New("new mesh alias must be provisioned disabled")
			}
			initial := model.LocalUsage{Email: email, Source: rand.Text()}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&initial).Error; err != nil {
				return nil, err
			}
			var local model.LocalUsage
			if err := tx.First(&local, "email = ?", email).Error; err != nil {
				return nil, err
			}
			if local.Billed != 0 || local.Source == "" {
				return nil, errors.New("historical alias requires an explicit accounting cutover")
			}
			binding = model.MeshBinding{Email: email, Subscription: p.Subscription, Owner: owner}
			meter := quotaescrow.Meter{Subscription: p.Subscription, Owner: owner, Source: local.Source, Epoch: p.Epoch}
			if err := tx.Create(&meter).Error; err != nil {
				return nil, err
			}
		} else if authorization.Revision < binding.AuthorizationRevision {
			return nil, errors.New("alias authorization revision regressed")
		}
		binding.AuthorizationRevision = authorization.Revision
		binding.AuthorizationFingerprint = authorization.Fingerprint
		if err := tx.Save(&binding).Error; err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	slices.Sort(emails)
	return emails, nil
}

func validateMeshBindingAuthorization(p quotaescrow.Policy, b model.MeshBinding) error {
	if p.Aliases == nil {
		if b.AuthorizationRevision != 0 || b.AuthorizationFingerprint != "" {
			return errors.New("legacy alias gained an unauthorized revision")
		}
		return nil
	}
	a, ok := p.Aliases[b.Owner][b.Email]
	if !ok || a.Revision != b.AuthorizationRevision || a.Fingerprint != b.AuthorizationFingerprint {
		return errors.New("binding differs from committed alias authorization")
	}
	return nil
}
