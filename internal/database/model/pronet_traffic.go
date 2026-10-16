package model

// Lifetime counters, deliberately independent of subscription quota resets.
// An empty OriginGuid is local; mirrors use the physical node's stable GUID.
type InboundTrafficDetail struct {
	RateParts     int64  `json:"rateParts" gorm:"primaryKey"`
	OriginGuid    string `json:"originGuid" gorm:"primaryKey"`
	InboundTag    string `json:"inboundTag" gorm:"primaryKey"`
	Email         string `json:"email" gorm:"primaryKey"`
	RawUp         int64  `json:"rawUp"`
	RawDown       int64  `json:"rawDown"`
	BilledUp      int64  `json:"billedUp"`
	BilledDown    int64  `json:"billedDown"`
	RemainderUp   int64  `json:"-"`
	RemainderDown int64  `json:"-"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime:false"`
}
