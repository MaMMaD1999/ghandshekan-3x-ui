package version

import "testing"

func TestBrandMigrationKeepsReleaseSequence(t *testing.T) {
	if order, ok := Compare("3.10.2-ghandshekan.25", "3.10.2-pronet.24"); !ok || order != 1 {
		t.Fatal(order, ok)
	}
	if order, ok := Compare("3.10.2-ghandshekan.25", "3.10.2-pronet.25"); !ok || order != 0 {
		t.Fatal(order, ok)
	}
}
