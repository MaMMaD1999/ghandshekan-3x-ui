package quotaescrow

import "testing"

func TestActivationPreservesExistingUsageExactlyOnce(t *testing.T) {
	p, k := fixture(t)
	p.AlreadyBilled = 600
	p.Grants = map[string]int64{"de": 200, "at": 100, "nl": 100}
	a := ledger(t, p)
	b := ledger(t, p)
	assertBilled(t, a, 600)
	r, err := a.Observe("at", k["at"], 40)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Merge([]SignedRow{r}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err = b.Merge(a.Snapshot()); err != nil {
			t.Fatal(err)
		}
	}
	assertBilled(t, a, 640)
	assertBilled(t, b, 640)
	if available, err := b.Available("at", 100); err != nil || available != 60 {
		t.Fatal(available, err)
	}
	p.Grants["de"] = 201
	if _, err = New(p); err == nil {
		t.Fatal("activation restored already consumed credit")
	}
}

func TestActivationOfAlreadyExhaustedSubscriptionCannotGrantCredit(t *testing.T) {
	p, _ := fixture(t)
	p.AlreadyBilled = 1100
	p.Grants = map[string]int64{"de": 0, "at": 0, "nl": 0}
	l := ledger(t, p)
	assertBilled(t, l, 1100)
	for id := range p.Grants {
		if n, err := l.Available(id, 100); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
	p.Grants["at"] = 1
	if _, err := New(p); err == nil {
		t.Fatal("overrun user obtained new credit")
	}
}
