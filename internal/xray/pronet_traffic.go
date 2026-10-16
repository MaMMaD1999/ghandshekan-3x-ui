package xray

import (
	"context"
	"encoding/base64"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"strings"
	"time"
)

func processDetailedTraffic(name string, value int64, rows map[string]*ClientTraffic) bool {
	parts := strings.Split(name, ">>>")
	if len(parts) != 5 || parts[0] != "pronet" || parts[3] != "traffic" {
		return false
	}
	tag, e1 := base64.RawURLEncoding.DecodeString(parts[1])
	email, e2 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || len(tag) == 0 || len(email) == 0 || (parts[4] != "uplink" && parts[4] != "downlink") {
		return true
	}
	key := "pronet:" + parts[1] + ":" + parts[2]
	row := rows[key]
	if row == nil {
		row = &ClientTraffic{Email: string(email), InboundTag: string(tag)}
		rows[key] = row
	}
	if parts[4] == "uplink" {
		row.Up = value
	} else {
		row.Down = value
	}
	return true
}

func (x *XrayAPI) HasProNetAccounting() bool {
	if x.StatsServiceClient == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := (*x.StatsServiceClient).GetStats(ctx, &statsService.GetStatsRequest{Name: "pronet>>>capability>>>1", Reset_: false})
	return err == nil && result.GetStat().GetValue() == 1
}
