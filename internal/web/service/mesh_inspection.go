package service

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

func (c *MeshControl) Inspect(signed quotaescrow.SignedInspection) (quotaescrow.Inventory, error) {
	var out quotaescrow.Inventory
	request, err := quotaescrow.VerifyInspection(signed, c.Authority, c.Owner, time.Now().Unix())
	if err != nil {
		return out, err
	}
	if c.DB == nil || len(c.Key) != ed25519.PrivateKeySize {
		return out, errors.New("inspection unavailable")
	}
	out.Owner, out.RequestHash = c.Owner, quotaescrow.InspectionHash(request)
	err = meshReportRead(c.DB, func(tx *gorm.DB) error {
		scopes, err := meshReportScopes(tx)
		if err != nil {
			return err
		}
		for _, email := range request.Emails {
			fingerprint, err := MeshAliasFingerprint(tx, email)
			if err != nil {
				return err
			}
			var client model.ClientRecord
			if err := tx.Where("email = ?", email).First(&client).Error; err != nil {
				return err
			}
			var local int64
			q := tx.Table("inbounds i").Joins("JOIN client_inbounds ci ON ci.inbound_id = i.id").Where("ci.client_id = ?", client.Id)
			if err := q.Session(&gorm.Session{}).Where("i.node_id IS NULL").Count(&local).Error; err != nil {
				return err
			}
			var children []string
			if err := q.Session(&gorm.Session{}).Joins("JOIN nodes n ON n.id = i.node_id").Distinct("n.guid").Order("n.guid").Pluck("n.guid", &children).Error; err != nil {
				return err
			}
			var binding model.MeshBinding
			err = tx.Where("email = ?", email).Take(&binding).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			out.Aliases = append(out.Aliases, quotaescrow.InspectedAlias{Claim: quotaescrow.AliasClaim{Email: email, Fingerprint: fingerprint}, Local: local > 0, Children: children, Subscription: binding.Subscription, Epoch: scopes[email].Epoch, Pending: scopes[email].Pending, Limit: client.TotalGB, ExpiresAt: client.ExpiryTime, Enabled: client.Enable})
		}
		return nil
	})
	if err != nil {
		return quotaescrow.Inventory{}, err
	}
	return quotaescrow.SignInventory(out, c.Key)
}

func (c *MeshControl) InspectionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mutual TLS required", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var signed quotaescrow.SignedInspection
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&signed) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid inspection", http.StatusBadRequest)
			return
		}
		result, err := c.Inspect(signed)
		if err != nil {
			http.Error(w, "inspection refused", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
