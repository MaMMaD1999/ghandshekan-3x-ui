package model

// LocalUsage is a durable monotonic, already-billed meter for this panel only.
// Unlike client_traffics on a master, it never includes imported node counters.
// Resets/renewals reset subscription epochs, not this source watermark.
type LocalUsage struct {
	Email  string `gorm:"primaryKey"`
	Source string `gorm:"not null"`
	Billed int64  `gorm:"not null"`
}

func (LocalUsage) TableName() string { return "mesh_local_usage" }
