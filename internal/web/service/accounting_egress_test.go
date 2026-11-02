package service

import (
	"encoding/json"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
	"reflect"
	"testing"
)

func TestAccountingBridgeIsExplicitAndPreservesExistingRuleOrder(t *testing.T) {
	for _, tc := range []struct {
		routing string
		want    bool
	}{
		{`{"rules":[]}`, false},
		{`{"rules":[{"inboundTag":["api"],"outboundTag":"proxy"}]}`, false},
		{`{"rules":[{"inboundTag":["accounting-sync"],"outboundTag":"missing"}]}`, false},
		{`{"rules":[{"inboundTag":["accounting-sync"],"outboundTag":"proxy"}]}`, true},
	} {
		cfg := &xray.Config{RouterConfig: json_util.RawMessage(tc.routing), OutboundConfigs: json_util.RawMessage(`[{"tag":"proxy","protocol":"freedom"}]`)}
		injectAccountingEgress(cfg)
		if (len(cfg.InboundConfigs) == 1) != tc.want {
			t.Fatalf("unexpected bridge for %s", tc.routing)
		}
		if !tc.want && string(cfg.RouterConfig) != tc.routing {
			t.Fatal("accounting bridge changed routing priority")
		}
		if tc.want {
			var before, after map[string]any
			json.Unmarshal([]byte(tc.routing), &before)
			json.Unmarshal(cfg.RouterConfig, &after)
			original := before["rules"].([]any)
			actual := after["rules"].([]any)
			if len(actual) != len(original)+1 || !reflect.DeepEqual(original, actual[:len(original)]) {
				t.Fatal("existing rule order changed")
			}
			last := actual[len(actual)-1].(map[string]any)
			if !reflect.DeepEqual(last["inboundTag"], []any{AccountingSyncInboundTag}) {
				t.Fatal("fallback affects other inbounds")
			}
			ib := cfg.InboundConfigs[0]
			if string(ib.Listen) != `"127.0.0.1"` || ib.Tag != AccountingSyncInboundTag {
				t.Fatal("bridge exposed or wrong tag")
			}
			injectAccountingEgress(cfg)
			if len(cfg.InboundConfigs) != 1 {
				t.Fatal("duplicate injection")
			}
		}
	}
}

func TestAccountingConditionalRuleCannotFallThroughDefault(t *testing.T) {
	cfg := &xray.Config{RouterConfig: json_util.RawMessage(`{"rules":[{"inboundTag":["accounting-sync"],"domain":["example.org"],"outboundTag":"proxy"}]}`), OutboundConfigs: json_util.RawMessage(`[{"tag":"proxy","protocol":"freedom"},{"tag":"accounting-sync-unmatched","protocol":"freedom"}]`)}
	injectAccountingEgress(cfg)
	var routing map[string]any
	var outbounds []map[string]any
	json.Unmarshal(cfg.RouterConfig, &routing)
	json.Unmarshal(cfg.OutboundConfigs, &outbounds)
	rules := routing["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	deny := outbounds[len(outbounds)-1]
	if deny["protocol"] != "blackhole" || last["outboundTag"] != deny["tag"] || deny["tag"] == "accounting-sync-unmatched" {
		t.Fatal("unmatched fallback may escape through default")
	}
}

func TestAccountingBridgePortExhaustionDoesNotStealAnotherInbound(t *testing.T) {
	cfg := &xray.Config{RouterConfig: json_util.RawMessage(`{"rules":[{"inboundTag":["accounting-sync"],"outboundTag":"proxy"}]}`), OutboundConfigs: json_util.RawMessage(`[{"tag":"proxy"}]`)}
	for p := 62780; p < 62790; p++ {
		cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{Port: p})
	}
	injectAccountingEgress(cfg)
	if len(cfg.InboundConfigs) != 10 {
		t.Fatal("bridge must stay unavailable when all reserved ports are occupied")
	}
}
