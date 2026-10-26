package model

// Lifetime counters, deliberately independent of subscription quota resets.
// An empty OriginGuid is local; mirrors use the physical node's stable GUID.
type InboundTrafficDetail struct {
	InboundName          string `json:"inboundName"`
	RateParts            int64  `json:"rateParts" gorm:"primaryKey"`
	OriginGuid           string `json:"originGuid" gorm:"primaryKey"`
	InboundTag           string `json:"inboundTag" gorm:"primaryKey"`
	Email                string `json:"email" gorm:"primaryKey"`
	RawUp                int64  `json:"rawUp"`
	RawDown              int64  `json:"rawDown"`
	BilledUp             int64  `json:"billedUp"`
	BilledDown           int64  `json:"billedDown"`
	RemainderUp          int64  `json:"-"`
	RemainderDown        int64  `json:"-"`
	UpdatedAt            int64  `json:"updatedAt" gorm:"autoUpdateTime:false"`
	ReportResetAt        int64  `json:"reportResetAt,omitempty"`
	ReportBaseRawUp      int64  `json:"reportBaseRawUp,omitempty"`
	ReportBaseRawDown    int64  `json:"reportBaseRawDown,omitempty"`
	ReportBaseBilledUp   int64  `json:"reportBaseBilledUp,omitempty"`
	ReportBaseBilledDown int64  `json:"reportBaseBilledDown,omitempty"`
}

// Minute buckets contain observed deltas, never another quota charge. Older
// lifetime usage is deliberately not assigned to a fabricated date.
type InboundTrafficHistory struct {
	Bucket               int64 `json:"bucket" gorm:"primaryKey;index:idx_traffic_history_email_bucket,priority:1"`
	InboundTrafficDetail `gorm:"embedded"`
}
