package sub

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

type hostToggleOutput struct {
	entries []string
	header  string
}

// Compare transport settings, not first-link display annotations or YAML names.
func captureHostToggle(t *testing.T) map[string]hostToggleOutput {
	t.Helper()
	out := map[string]hostToggleOutput{}
	links, _, _, traffic, err := NewSubService("").GetSubs("toggle-sub", "request.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range splitLinkLines(strings.Join(links, "\n")) {
		out["raw"] = hostToggleOutput{entries: append(out["raw"].entries, strings.SplitN(link, "#", 2)[0])}
	}
	raw := out["raw"]
	raw.header = NewSubService("").subscriptionUserinfo(traffic)
	out["raw"] = raw
	body, header, err := NewSubJsonService("", "", "", "", NewSubService("")).GetJson("toggle-sub", "request.example", true)
	if err != nil {
		t.Fatal(err)
	}
	j := hostToggleOutput{header: header}
	if body != "" {
		var docs []map[string]any
		if err := json.Unmarshal([]byte(body), &docs); err != nil {
			t.Fatal(err)
		}
		for _, doc := range docs {
			delete(doc, "remarks")
			b, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			j.entries = append(j.entries, string(b))
		}
	}
	out["json"] = j
	body, header, err = NewSubClashService(false, "", NewSubService("")).GetClash("toggle-sub", "request.example")
	if err != nil {
		t.Fatal(err)
	}
	c := hostToggleOutput{header: header}
	if body != "" {
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
		for _, proxy := range doc.Proxies {
			delete(proxy, "name")
			b, err := json.Marshal(proxy)
			if err != nil {
				t.Fatal(err)
			}
			c.entries = append(c.entries, string(b))
		}
	}
	out["clash"] = c
	for key, result := range out {
		sort.Strings(result.entries)
		out[key] = result
	}
	return out
}

func TestHostToggleOnlyRemovesSelectedEndpointsAcrossFormats(t *testing.T) {
	for _, filter := range []string{"disabled", "excluded"} {
		t.Run(filter, func(t *testing.T) {
			seedSubDB(t)
			a := seedSubInbound(t, "toggle-sub", "a", 4541, 1, wsTLSStream)
			b := seedSubInbound(t, "toggle-sub", "b", 4542, 2, wsTLSStream)
			first := seedHost(t, &model.Host{InboundId: a.Id, GroupId: "first", Address: "first.example", Port: 8443, Remark: "first", Security: "none", Path: "/first", HostHeader: "first.host"})
			second := seedHost(t, &model.Host{InboundId: a.Id, GroupId: "second", SortOrder: 1, Address: "second.example", Port: 9443, Remark: "second", Security: "same"})
			seedHost(t, &model.Host{InboundId: b.Id, GroupId: "sibling", Address: "sibling.example", Port: 7443, Remark: "sibling"})
			before := captureHostToggle(t)
			for key, result := range before {
				if len(result.entries) != 3 {
					t.Fatalf("%s before=%v", key, result.entries)
				}
			}
			for i, h := range []*model.Host{first, second} {
				var err error
				if filter == "disabled" {
					err = database.GetDB().Model(&model.Host{}).Where("id = ?", h.Id).Update("is_disabled", true).Error
				} else {
					err = database.GetDB().Model(&model.Host{}).Where("id = ?", h.Id).Update("exclude_from_sub_types", `["raw","json","clash"]`).Error
				}
				if err != nil {
					t.Fatal(err)
				}
				after := captureHostToggle(t)
				for key, original := range before {
					var want []string
					for _, entry := range original.entries {
						if !strings.Contains(entry, "first.example") && (i == 0 || !strings.Contains(entry, "second.example")) {
							want = append(want, entry)
						}
					}
					if !reflect.DeepEqual(after[key].entries, want) {
						t.Fatalf("%s %s toggle %d changed siblings or resurrected fallback\ngot %v\nwant %v", filter, key, i, after[key].entries, want)
					}
					if after[key].header != original.header {
						t.Fatalf("%s toggle changed quota header: %q -> %q", key, original.header, after[key].header)
					}
				}
			}
			// Share/QR and inbound exports must make the same choice as subscriptions.
			p := NewLinkProvider()
			if links := p.LinksForClient("request.example", a, "a@e"); len(links) != 0 {
				t.Fatalf("filtered host client export leaked legacy: %v", links)
			}
			if links := p.LinksForInbounds("request.example", []*model.Inbound{a}); len(links) != 0 {
				t.Fatalf("filtered host inbound export leaked legacy: %v", links)
			}
		})
	}
}

func TestJSONHostRenderingDoesNotMutateSourceInbound(t *testing.T) {
	seedSubDB(t)
	ib := seedSubInbound(t, "toggle-sub", "source", 4543, 1, wsTLSStream)
	before := *ib
	svc := NewSubService("")
	svc.PrepareForRequest("request.example")
	clients := svc.matchingClients(ib, "toggle-sub")
	if len(clients) != 1 {
		t.Fatalf("clients=%d", len(clients))
	}
	clone := *ib
	injectExternalProxy(&clone, []map[string]any{{"isHost": true, "dest": "override.example", "port": float64(9443), "forceTls": "same"}})
	stream := clone.StreamSettings
	NewSubJsonService("", "", "", "", svc).getConfig(svc, &clone, clients[0], "request.example")
	if clone.Listen != before.Listen || clone.Port != before.Port || clone.StreamSettings != stream {
		t.Fatalf("host render mutated source inbound address/port/stream")
	}
}

func TestAllHostsFilteredKeepQuotaWithoutLegacyEndpoints(t *testing.T) {
	seedSubDB(t)
	ib := seedSubInbound(t, "toggle-sub", "only", 4544, 1, `{"network":"ws","security":"tls","externalProxy":[{"dest":"legacy.example","port":443,"forceTls":"same"}]}`)
	seedHost(t, &model.Host{InboundId: ib.Id, Address: "disabled.example", IsDisabled: true})
	for format, result := range captureHostToggle(t) {
		if len(result.entries) != 0 {
			t.Fatalf("%s returned endpoints with all hosts disabled: %v", format, result.entries)
		}
		if result.header == "" {
			t.Fatalf("%s lost the subscription quota header", format)
		}
	}
}

func TestHostFormatExclusionDoesNotHideOtherFormats(t *testing.T) {
	seedSubDB(t)
	ib := seedSubInbound(t, "toggle-sub", "formats", 4545, 1, wsTLSStream)
	seedHost(t, &model.Host{InboundId: ib.Id, Address: "raw-and-json.example", Remark: "visible", ExcludeFromSubTypes: []string{"clash"}})
	got := captureHostToggle(t)
	if len(got["raw"].entries) != 1 || len(got["json"].entries) != 1 || len(got["clash"].entries) != 0 {
		t.Fatalf("format-specific exclusion returned wrong counts: %+v", got)
	}
}
