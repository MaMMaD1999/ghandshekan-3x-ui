package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/meshconsensus"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
	"gorm.io/gorm"
)

// Stored in the private enrollment journal, never in an API-visible client
// record. Save the exact command before submitting it: a lost reply must not
// reconstruct expected revisions from newer state and issue a second mutation.
type meshAliasJob struct {
	ID          string `gorm:"primaryKey"`
	InputJSON   string
	CommandJSON string
	Committed   bool
	Version     uint64
	PolicyHash  string
	Generation  uint64
}

func (meshAliasJob) TableName() string { return "mesh_alias_jobs" }

type MeshAliasInput struct {
	Subscription string   `json:"subscription"`
	ControlEpoch string   `json:"controlEpoch,omitempty"`
	Epoch        string   `json:"epoch,omitempty"`
	Email        string   `json:"email"`
	Revoke       bool     `json:"revoke"`
	Roots        []string `json:"roots,omitempty"`
}

type MeshAliasResult struct {
	Operation          string `json:"operation"`
	MajorityCommitted  bool   `json:"majorityCommitted"`
	ApplicationPending bool   `json:"applicationPending"`
	PolicyVersion      uint64 `json:"policyVersion"`
	PolicyHash         string `json:"policyHash"`
	ResetGeneration    uint64 `json:"resetGeneration"`
}

func QueueMeshAlias(ctx context.Context, input MeshAliasInput, key string) (MeshAliasResult, error) {
	a := activeMeshEnrollment.Load()
	if a == nil {
		manager := activeMeshAdministrator.Load()
		if !input.Revoke || manager == nil || manager.Quorum == nil || manager.Quorum.revocations == nil {
			return MeshAliasResult{}, errors.New("device membership manager is not configured")
		}
		a = manager.Quorum.revocations
	}
	return a.QueueAlias(ctx, input, key)
}

func (a *MeshEnrollmentAdministrator) QueueAlias(ctx context.Context, input MeshAliasInput, key string) (MeshAliasResult, error) {
	var out MeshAliasResult
	if a.aliasPolicy == nil || a.aliasExecute == nil || a.aliasSync == nil {
		return out, errors.New("device majority controller unavailable")
	}
	if input.Subscription == "" || len(input.Subscription) > 512 || input.Email == "" || len(input.Email) > 512 || strings.ContainsAny(input.Email, "\x00\r\n") {
		return out, errors.New("invalid device membership scope")
	}
	id, err := meshOperationID(input.Subscription, "device", key)
	if err != nil {
		return out, err
	}
	encoded, _ := json.Marshal(input)
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	db := a.manager.Coordinator.DB
	var job meshAliasJob
	err = db.First(&job, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		policy, err := a.aliasPolicy(input.Subscription)
		if err != nil {
			return out, err
		}
		if (input.ControlEpoch != "" || input.Epoch != "") && (input.ControlEpoch != policy.ControlEpoch || input.Epoch != policy.Epoch) {
			return out, errors.New("device control or lifetime identity changed")
		}
		patches, err := a.builder.AliasChangesForRoots(ctx, policy, a.manager.Local.Owner, input.Email, input.Revoke, input.Roots)
		if err != nil {
			return out, err
		}
		command := meshconsensus.Command{ID: id, Subscription: input.Subscription, Kind: "alias", AliasBatch: patches, DeviceHash: quotaescrow.DeviceAuthorizationHash(policy, input.Email)}
		body, err := json.Marshal(command)
		if err != nil {
			return out, err
		}
		job = meshAliasJob{ID: id, InputJSON: string(encoded), CommandJSON: string(body)}
		if err := db.Create(&job).Error; err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else if job.InputJSON != string(encoded) {
		return out, errors.New("device operation ID reused with different inputs")
	}
	return a.executeAliasJob(ctx, &job)
}

func (a *MeshEnrollmentAdministrator) executeAliasJob(ctx context.Context, job *meshAliasJob) (MeshAliasResult, error) {
	out := MeshAliasResult{Operation: job.ID, MajorityCommitted: job.Committed, ApplicationPending: true}
	var command meshconsensus.Command
	if json.Unmarshal([]byte(job.CommandJSON), &command) != nil || command.ID != job.ID || command.Kind != "alias" || len(command.AliasBatch) == 0 || command.DeviceHash == "" {
		return out, errors.New("invalid saved device membership command")
	}
	if !job.Committed || job.PolicyHash == "" {
		result, err := a.aliasExecute(ctx, command)
		if err != nil {
			return out, err
		}
		if result.Error != "" {
			return out, errors.New(result.Error)
		}
		if result.Update == nil || result.Update.ID != job.ID || result.Update.Next.Subscription != command.Subscription || result.Update.Kind != "alias" {
			return out, errors.New("missing committed device membership result")
		}
		job.Committed, job.Version = true, result.Update.Next.Version
		job.PolicyHash, job.Generation = quotaescrow.PolicyHash(result.Update.Next), result.Update.Next.ResetGeneration
		if err := a.manager.Coordinator.DB.Save(job).Error; err != nil {
			return out, err
		}
	}
	out.MajorityCommitted = true
	out.PolicyVersion, out.PolicyHash, out.ResetGeneration = job.Version, job.PolicyHash, job.Generation
	// A successful local application says nothing about an offline member.
	// Keep applicationPending true; peers use the ordinary certified catch-up.
	return out, a.aliasSync(ctx, command.Subscription, job.Version)
}

func (a *MeshEnrollmentAdministrator) resumeAliasJobs(ctx context.Context, cursor string) string {
	if a.aliasExecute == nil {
		return ""
	}
	a.aliasMu.Lock()
	defer a.aliasMu.Unlock()
	var jobs []meshAliasJob
	if a.manager.Coordinator.DB.Where("committed = ? AND id > ?", false, cursor).Order("id").Limit(4).Find(&jobs).Error != nil || len(jobs) == 0 {
		return ""
	}
	for i := range jobs {
		if ctx.Err() != nil {
			return cursor
		}
		_, _ = a.executeAliasJob(ctx, &jobs[i])
		cursor = jobs[i].ID
	}
	return cursor
}
