package model

// MeshControlState persists the admission barrier before touching Xray. A
// timeout/restart does not clear it. Prepared receipts and completed operations
// remain available for idempotent retries and independent restore checkpoints.
type MeshControlState struct {
	ID           string `gorm:"primaryKey"`
	Subscription string `gorm:"not null;index"`
	PlanHash     string `gorm:"not null"`
	PlanJSON     string `gorm:"not null"`
	Stage        int    `gorm:"not null;default:0"` // 0 fencing, 1 prepared, 2 committed
	ReceiptJSON  string `gorm:"not null;default:''"`
	CommitHash   string `gorm:"not null;default:''"`
}

func (MeshControlState) TableName() string { return "mesh_control_states" }
