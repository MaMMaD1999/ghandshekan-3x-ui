package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Native enrollment preserves the subscription configured in this panel. It
// accepts no quota from the browser and never groups clients by display name.
// Historical bytes are captured by the existing signed/drained cutover.
func (a *MeshEnrollmentAdministrator) QueueNative(ctx context.Context, email, key string) (MeshOperationResult, error) {
	var input MeshEnrollmentInput
	var expectedState string
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 512 || key == "" {
		return MeshOperationResult{}, errors.New("native client email and Idempotency-Key are required")
	}
	err := meshReportRead(a.manager.Local.DB, func(tx *gorm.DB) error {
		var client model.ClientRecord
		if err := tx.First(&client, "email = ?", email).Error; err != nil {
			return err
		}
		// Include the durable row identity: deleting/recreating an email must
		// not reuse a previous subscriber's control scope or consumed bytes.
		credential, _ := json.Marshal([]any{client.Id, client.CreatedAt, client.SubID, client.UUID, client.Password, client.Auth})
		input.Subscription = NativeMeshSubscription(a.manager.Local.Owner, email, string(credential))
		input.Emails = []string{email}
		input.Limit, input.Disabled, input.Unlimited = client.TotalGB, !client.Enable, client.TotalGB == 0
		input.ExpiresAt = client.ExpiryTime / 1000
		if client.ExpiryTime > 0 && client.ExpiryTime%1000 != 0 {
			input.ExpiresAt++
		}
		var err error
		expectedState, err = MeshEnrollmentState(tx, email)
		return err
	})
	if err != nil {
		return MeshOperationResult{}, err
	}
	id, err := meshOperationID(input.Subscription, "enroll", key)
	if err != nil {
		return MeshOperationResult{}, err
	}
	var job quotaescrow.ControlJob
	err = a.manager.Coordinator.DB.First(&job, "id = ?", id).Error
	if err == nil {
		// A lost reply is a lookup of the original intent, including after
		// normal renewals/resets have changed the current client settings.
		var saved quotaescrow.ControlTarget
		if json.Unmarshal([]byte(job.TargetJSON), &saved) != nil {
			return MeshOperationResult{}, errors.New("invalid saved native enrollment")
		}
		input.Limit, input.ExpiresAt = saved.Limit, saved.ExpiresAt
		input.Disabled, input.Unlimited = saved.Disabled, saved.Unlimited
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return MeshOperationResult{}, err
	} else {
		var client model.ClientRecord
		if err := a.manager.Local.DB.First(&client, "email = ?", email).Error; err != nil {
			return MeshOperationResult{}, err
		}
		if client.ExpiryTime < 0 {
			return MeshOperationResult{}, errors.New("activate first-use expiry before native enrollment")
		}
		if client.Reset != 0 || client.ResetDay != 0 || client.ResetWeekday != 0 || client.ResetMax != 0 {
			return MeshOperationResult{}, errors.New("legacy automatic renewal must be migrated explicitly before enrollment")
		}
	}
	result, err := a.queue(ctx, input, key, expectedState)
	if err != nil {
		return result, fmt.Errorf("native enrollment: %w", err)
	}
	return result, nil
}

func QueueNativeMeshEnrollment(ctx context.Context, email, key string) (MeshOperationResult, error) {
	a := activeMeshEnrollment.Load()
	if a == nil {
		return MeshOperationResult{}, errors.New("initial enrollment manager is not configured on this panel")
	}
	return a.QueueNative(ctx, email, key)
}

func (a *MeshEnrollmentAdministrator) nextNativeEnrollment(after int) (*model.ClientRecord, error) {
	var row model.ClientRecord
	query := a.manager.Local.DB.Model(&model.ClientRecord{}).
		Where("clients.id > ? AND clients.expiry_time >= 0 AND clients.reset = 0 AND clients.reset_day = 0 AND clients.reset_weekday = 0 AND clients.reset_max = 0", after).
		Where("COALESCE(clients.comment, '') <> ?", "GhandShekan application device").
		Where("EXISTS (SELECT 1 FROM client_inbounds ci WHERE ci.client_id = clients.id)").
		Where("NOT EXISTS (SELECT 1 FROM mesh_client_bindings b WHERE b.email = clients.email)")
	if len(a.nativeExclude) != 0 {
		query = query.Where("clients.email NOT IN ?", a.nativeExclude)
	}
	err := query.Order("clients.id").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &row, err
}

// Operator opt-in only. New application aliases carry an explicit marker;
// pre-existing application aliases and protected customers are excluded by the
// host configuration generated from their verified ownership inventory.
func (a *MeshEnrollmentAdministrator) runNativeEnrollment(ctx context.Context) {
	cursor := 0
	lastLog := time.Time{}
	for ctx.Err() == nil {
		// Only this opt-in and exclusion list can reload. Membership and keys
		// remain pinned by the running controller and cannot change underneath it.
		err := a.reloadNativeEnrollment()
		var row *model.ClientRecord
		if err == nil && a.nativeEnabled {
			row, err = a.nextNativeEnrollment(cursor)
		}
		delay := 2 * time.Second
		if !a.nativeEnabled {
			delay = 5 * time.Second
		} else if err == nil && row == nil {
			cursor = 0
			delay = 30 * time.Second
		}
		if err == nil && row != nil {
			cursor = row.Id
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err = a.QueueNative(bounded, row.Email, "native-automatic-v1")
			cancel()
		}
		if err != nil && time.Since(lastLog) > time.Minute {
			logger.Warning("native mesh enrollment retained its original operation: ", err)
			lastLog = time.Now()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (a *MeshEnrollmentAdministrator) reloadNativeEnrollment() error {
	if a.nativeConfigPath == "" {
		return nil
	}
	c, _, err := LoadMeshConfig(a.nativeConfigPath)
	if err != nil {
		a.nativeEnabled = false
		return err
	}
	coordinator := a.manager.Coordinator
	if c.Owner != a.manager.Local.Owner || c.ControlEpoch != coordinator.ControlEpoch ||
		!bytes.Equal(c.Authority, coordinator.Authority.Public().(ed25519.PublicKey)) ||
		!reflect.DeepEqual(c.PeerKeys, coordinator.ControlKeys) {
		a.nativeEnabled = false
		return errors.New("live enrollment registry changed; explicit restart/reconfiguration required")
	}
	a.nativeEnabled, a.nativeExclude = c.NativeEnrollment, slices.Clone(c.NativeEnrollmentExclude)
	return nil
}
