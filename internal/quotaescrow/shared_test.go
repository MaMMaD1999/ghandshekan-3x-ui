package quotaescrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSharedQuotaUsesLatestGlobalViewWithoutReservedOrDuplicateCharges(t *testing.T) {
	pubA, aKey, _ := ed25519.GenerateKey(rand.Reader)
	pubB, bKey, _ := ed25519.GenerateKey(rand.Reader)
	p := Policy{Mode: "shared", Subscription: "sub", Epoch: "cycle", Limit: 10, ExpiresAt: 100, Grants: map[string]int64{"a": 0, "b": 0}, Keys: map[string][]byte{"a": pubA, "b": pubB}}
	a, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New(p)
	rowA, err := a.Observe("a", aKey, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Merge([]SignedRow{rowA}); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge([]SignedRow{rowA}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		l     *Ledger
		owner string
	}{{a, "a"}, {b, "b"}} {
		left, err := entry.l.Available(entry.owner, 10)
		if err != nil || left != 7 {
			t.Fatal(left, err)
		}
	}
	// Partition: both still have a signed view with seven remaining bytes.
	// A consumes another seven, B seven. Actual total is 17, not 10 or 24.
	rowA, err = a.Observe("a", aKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	rowB, err := b.Observe("b", bKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Merge([]SignedRow{rowA}); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge([]SignedRow{rowB}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		for _, entry := range []struct {
			l     *Ledger
			owner string
		}{{a, "a"}, {b, "b"}} {
			if err := entry.l.Merge([]SignedRow{rowB, rowA}); err != nil {
				t.Fatal(err)
			}
			used, err := entry.l.Billed()
			if err != nil || used != 17 {
				t.Fatal("reconciliation changed actual usage", used, err)
			}
			left, err := entry.l.Available(entry.owner, 10)
			if err != nil || left != 0 {
				t.Fatal("over-limit member stayed admitted", left, err)
			}
		}
	}
	// The mode never spends or bills an arbitrary reservation; expiry is local.
	fresh, _ := New(p)
	if _, err := fresh.Propose("a", aKey, 1, "b", 10); err == nil {
		t.Fatal("transferred nonexistent reserved credit")
	}
	if left, err := fresh.Available("a", 100); err != nil || left != 0 {
		t.Fatal("expiry required master", left, err)
	}
	p.Grants["a"] = 1
	if _, err := New(p); err == nil {
		t.Fatal("mixed shared quota with escrow allocation")
	}
}
