package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestConfigGateProtocolGuard(t *testing.T) {
	for _, tc := range []struct {
		protocol, settings string
		supported          bool
	}{
		{"vless", `{"clients":[{"email":"a"}]}`, true},
		{"vmess", `{"clients":[{"email":"a"}]}`, true},
		{"trojan", `{"clients":[{"email":"a"}]}`, true},
		{"shadowsocks", `{"clients":[{"email":"a"}]}`, false},
		{"vless", `{"clients":[{"email":"a","reverse":{"tag":"r"}}]}`, false},
		{"vless", `{"clients":[{"id":"uuid"}]}`, false},
		{"vless", `{`, false},
	} {
		cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{{Protocol: tc.protocol, Settings: json_util.RawMessage(tc.settings)}}}
		_, ok := configGateUsers(cfg)
		if ok != tc.supported {
			t.Fatalf("%s %s: supported=%v", tc.protocol, tc.settings, ok)
		}
	}
}
