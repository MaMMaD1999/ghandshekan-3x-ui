package model

// Presentation boundary only: lifetime ledgers remain monotonic for billing
// and master/node deduplication across a subscription traffic reset.
type InboundTrafficReportBaseline struct {
	InboundTrafficDetail `gorm:"embedded"`
	ResetAt              int64 `json:"resetAt"`
}
