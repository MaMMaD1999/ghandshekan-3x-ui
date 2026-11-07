package quotaescrow

import "testing"

func TestFrozenHistoricalUsageIncludesUnsyncedBytesExactlyOnce(t *testing.T) {
	// Master already counted 40 local + 60 from AT. AT's 60 included 20 local
	// and 40 from NL. After the final drain AT has 25 local, NL 50 local.
	// Correct result is 115, not 165/215 from adding aggregate snapshots.
	snapshots := []LegacySnapshot{
		{Owner: "de", Aliases: map[string]LegacyAliasSnapshot{"phone": {Total: LegacyCounter{Down: 100}, Imports: []LegacyImport{{Owner: "at", Alias: "phone", Counter: LegacyCounter{Down: 60}}}}}},
		{Owner: "at", Aliases: map[string]LegacyAliasSnapshot{"phone": {Total: LegacyCounter{Down: 65}, Imports: []LegacyImport{{Owner: "nl", Alias: "phone", Counter: LegacyCounter{Down: 40}}}}}},
		{Owner: "nl", Aliases: map[string]LegacyAliasSnapshot{"phone": {Total: LegacyCounter{Down: 50}}}},
	}
	roots := []LegacyRoot{{Owner: "de", Alias: "phone"}}
	for i := 0; i < 3; i++ {
		got, err := FrozenHistoricalUsage(roots, snapshots)
		if err != nil || got != 115 {
			t.Fatal(got, err)
		}
	}
	// A child reset its own cycle earlier. The old history remains correctly
	// included in the parent's residual; its new cycle is not counted twice.
	snapshots[1].Aliases["phone"] = LegacyAliasSnapshot{Total: LegacyCounter{Down: 65}, Imports: []LegacyImport{{Owner: "nl", Alias: "phone", Counter: LegacyCounter{Down: 5}}}}
	snapshots[2].Aliases["phone"] = LegacyAliasSnapshot{Total: LegacyCounter{Down: 8}}
	got, err := FrozenHistoricalUsage(roots, snapshots)
	if err != nil || got != 108 {
		t.Fatal("child cycle reset lost history", got, err)
	}
}

func TestFrozenHistoricalUsageRefusesAmbiguousGraphs(t *testing.T) {
	for _, kind := range []string{"missing", "cycle", "duplicate", "negative-residual", "unreachable", "child-reset"} {
		t.Run(kind, func(t *testing.T) {
			a := LegacyAliasSnapshot{Total: LegacyCounter{Down: 10}, Imports: []LegacyImport{{Owner: "b", Alias: "x", Counter: LegacyCounter{Down: 5}}}}
			b := LegacyAliasSnapshot{Total: LegacyCounter{Down: 6}}
			snapshots := []LegacySnapshot{{Owner: "a", Aliases: map[string]LegacyAliasSnapshot{"x": a}}, {Owner: "b", Aliases: map[string]LegacyAliasSnapshot{"x": b}}}
			switch kind {
			case "missing":
				snapshots = snapshots[:1]
			case "cycle":
				b.Imports = []LegacyImport{{Owner: "a", Alias: "x", Counter: LegacyCounter{Down: 0}}}
				snapshots[1].Aliases["x"] = b
			case "duplicate":
				a.Imports = append(a.Imports, a.Imports[0])
				snapshots[0].Aliases["x"] = a
			case "negative-residual":
				a.Imports[0].Counter.Down = 11
				snapshots[0].Aliases["x"] = a
			case "unreachable":
				snapshots = append(snapshots, LegacySnapshot{Owner: "c", Aliases: map[string]LegacyAliasSnapshot{"x": b}})
			case "child-reset":
				b.Total.Down = 3
				snapshots[1].Aliases["x"] = b
			}
			if _, err := FrozenHistoricalUsage([]LegacyRoot{{Owner: "a", Alias: "x"}}, snapshots); err == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}
