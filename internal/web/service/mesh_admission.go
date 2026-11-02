package service

import (
	"encoding/json"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// FilterMeshInbound copies the runtime view only. Stored enable flags and
// master-owned settings are not modified by a temporary local quota gate.
func FilterMeshInbound(inbound *model.Inbound) (*model.Inbound, error) {
	blocked, err := MeshBlockedEmails(database.GetDB(), time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if len(blocked) == 0 {
		return inbound, nil
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return nil, err
	}
	clients, ok := settings["clients"].([]any)
	if !ok {
		return inbound, nil
	}
	kept := make([]any, 0, len(clients))
	for _, client := range clients {
		row, _ := client.(map[string]any)
		email, _ := row["email"].(string)
		if !blocked[email] {
			kept = append(kept, client)
		}
	}
	if len(kept) == len(clients) {
		return inbound, nil
	}
	settings["clients"] = kept
	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	copy := *inbound
	copy.Settings = string(encoded)
	return &copy, nil
}

// MeshBlockedEmails reads durable local admission, independently of master
// connectivity. Missing/corrupt policies fail closed for the enrolled alias;
// unbound legacy clients retain their ordinary admission behavior.
func MeshBlockedEmails(db *gorm.DB, now int64) (map[string]bool, error) {
	var bindings []model.MeshBinding
	if err := db.Find(&bindings).Error; err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	decisions := map[[2]string]bool{}
	store := quotaescrow.NewStore(db)
	for _, b := range bindings {
		key := [2]string{b.Subscription, b.Owner}
		deny, known := decisions[key]
		if !known {
			remaining, err := store.Admission(b.Subscription, b.Owner, now)
			deny = err != nil || remaining <= 0
			decisions[key] = deny
		}
		if deny {
			blocked[b.Email] = true
		}
	}
	return blocked, nil
}

// MeshClientAllowed is also used by the hot API path. A master re-pushing its
// old enabled client cannot bypass a locally exhausted or fenced mesh epoch.
func MeshClientAllowed(email string) (bool, error) {
	db := database.GetDB()
	var bindings []model.MeshBinding
	if err := db.Where("email = ?", email).Find(&bindings).Error; err != nil {
		return false, err
	}
	if len(bindings) == 0 {
		return true, nil
	}
	n, err := quotaescrow.NewStore(db).Admission(bindings[0].Subscription, bindings[0].Owner, time.Now().Unix())
	if err != nil {
		return false, nil
	}
	return n > 0, nil
}
