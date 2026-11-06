package service

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// Gate only protocols whose authenticated session owns its transport. Other
// protocols retain the established restart fallback until their UDP/reverse
// paths have dedicated acceptance coverage.
func configGateUsers(config *xray.Config) ([]string, bool) {
	if config == nil {
		return nil, false
	}
	var emails []string
	for _, inbound := range config.InboundConfigs {
		var settings struct {
			Clients []struct {
				Email   string          `json:"email"`
				Reverse json.RawMessage `json:"reverse"`
			} `json:"clients"`
		}
		if len(inbound.Settings) == 0 {
			continue
		}
		if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
			return nil, false
		}
		for _, client := range settings.Clients {
			if client.Email == "" || (inbound.Protocol != "vless" && inbound.Protocol != "vmess" && inbound.Protocol != "trojan") || (len(client.Reverse) > 0 && string(client.Reverse) != "null") {
				return nil, false
			}
			emails = append(emails, client.Email)
		}
	}
	return emails, true
}
