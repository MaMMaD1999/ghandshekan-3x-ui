package model

// MeshBinding is opt-in: an existing client is never implicitly enrolled based
// on its name, port or the presence of a local traffic meter.
type MeshBinding struct {
	Email        string `gorm:"primaryKey"`
	Subscription string `gorm:"not null;index"`
	Owner        string `gorm:"not null"`
}

func (MeshBinding) TableName() string { return "mesh_client_bindings" }
