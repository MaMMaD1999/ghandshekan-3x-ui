package service

import (
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// AccountingSyncInboundTag is reserved for the LAST-resort accounting transport.
// A routing rule prepares a bridge; it never changes transport preference.
const AccountingSyncInboundTag = "accounting-sync"

func injectAccountingEgress(cfg *xray.Config) {
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag == AccountingSyncInboundTag {
			return
		}
	}
	var routing map[string]any
	if json.Unmarshal(cfg.RouterConfig, &routing) != nil {
		return
	}
	rules, _ := routing["rules"].([]any)
	configured := false
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tags, _ := rule["inboundTag"].([]any)
		for _, tag := range tags {
			if tag != AccountingSyncInboundTag {
				continue
			}
			outbound, _ := rule["outboundTag"].(string)
			balancer, _ := rule["balancerTag"].(string)
			if outboundTagExists(cfg.OutboundConfigs, outbound) || (balancer != "" && routingTagIsBalancer(routing, balancer)) {
				configured = true
			}
		}
	}
	if !configured {
		return
	}
	used := make(map[int]bool)
	for _, inbound := range cfg.InboundConfigs {
		used[inbound.Port] = true
	}
	for port := 62780; port < 62790; port++ {
		if used[port] {
			continue
		}
		// Conditional administrator rules may not match this destination. Do not
		// let accounting traffic silently escape through Xray's default outbound.
		var outbounds []map[string]any
		if json.Unmarshal(cfg.OutboundConfigs, &outbounds) != nil {
			return
		}
		denyTag := AccountingSyncInboundTag + "-unmatched"
		for suffix := 1; outboundTagExists(cfg.OutboundConfigs, denyTag); suffix++ {
			denyTag = fmt.Sprintf("%s-unmatched-%d", AccountingSyncInboundTag, suffix)
		}
		outbounds = append(outbounds, map[string]any{"tag": denyTag, "protocol": "blackhole", "settings": map[string]any{}})
		routing["rules"] = append(rules, map[string]any{"type": "field", "inboundTag": []string{AccountingSyncInboundTag}, "outboundTag": denyTag})
		encodedOut, err := json.Marshal(outbounds)
		if err != nil {
			return
		}
		encodedRouting, err := json.Marshal(routing)
		if err != nil {
			return
		}
		cfg.OutboundConfigs = encodedOut
		cfg.RouterConfig = encodedRouting
		cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{
			Listen: json_util.RawMessage(`"127.0.0.1"`), Port: port,
			Protocol: "socks", Settings: json_util.RawMessage(`{"auth":"noauth","udp":false}`),
			Tag: AccountingSyncInboundTag,
		})
		return
	}
}

// This must be requested only after direct and mesh relay attempts have failed.
// Missing bridge is an unavailable fallback, NOT permission to use panel-egress.
func (s *SettingService) AccountingSyncProxyURL() string {
	proc := XrayProcess()
	if proc == nil || !proc.IsRunning() {
		return ""
	}
	cfg := proc.GetConfig()
	if cfg == nil {
		return ""
	}
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag == AccountingSyncInboundTag && string(inbound.Listen) == `"127.0.0.1"` && inbound.Protocol == "socks" && inbound.Port >= 62780 && inbound.Port < 62790 {
			return fmt.Sprintf("socks5://127.0.0.1:%d", inbound.Port)
		}
	}
	return ""
}
