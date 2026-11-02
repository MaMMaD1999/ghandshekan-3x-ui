package quotaescrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

func fixture(t *testing.T) (Policy, map[string]ed25519.PrivateKey) {
	t.Helper()
	p := Policy{Subscription: "user-1", Epoch: "reset-1", Limit: 1000, ExpiresAt: 5000, Grants: map[string]int64{"de": 400, "at": 300, "nl": 300}, Keys: map[string][]byte{}}
	keys := map[string]ed25519.PrivateKey{}
	for id := range p.Grants {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.Keys[id] = pub
		keys[id] = key
	}
	return p, keys
}
func ledger(t *testing.T, p Policy) *Ledger {
	t.Helper()
	l, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func apply(t *testing.T, l *Ledger, id string, k ed25519.PrivateKey, n int64, to string) SignedRow {
	t.Helper()
	s, err := l.Propose(id, k, n, to, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Merge([]SignedRow{s}); err != nil {
		t.Fatal(err)
	}
	return s
}
func assertBilled(t *testing.T, l *Ledger, want int64) {
	t.Helper()
	got, err := l.Billed()
	if err != nil || got != want {
		t.Fatalf("billed=%d err=%v want=%d", got, err, want)
	}
}

func TestOfflineMembersSpendOnlyTheirOwnRights(t *testing.T) {
	p, k := fixture(t)
	de, at, nl := ledger(t, p), ledger(t, p), ledger(t, p)
	apply(t, de, "de", k["de"], 400, "")
	apply(t, at, "at", k["at"], 300, "")
	apply(t, nl, "nl", k["nl"], 300, "")
	for id, l := range map[string]*Ledger{"de": de, "at": at, "nl": nl} {
		if _, err := l.Propose(id, k[id], 1, "", 100); !errors.Is(err, ErrInsufficient) {
			t.Fatalf("partition overspend %s: %v", id, err)
		}
	}
	for _, l := range []*Ledger{de, at, nl} {
		for _, peer := range []*Ledger{de, at, nl} {
			if err := l.Merge(peer.Snapshot()); err != nil {
				t.Fatal(err)
			}
		}
		assertBilled(t, l, 1000)
	}
}
func TestCreditTransferIsNotUsageAndDuplicateReportsDoNotBillTwice(t *testing.T) {
	p, k := fixture(t)
	a, b := ledger(t, p), ledger(t, p)
	transfer := apply(t, a, "de", k["de"], 200, "at")
	assertBilled(t, a, 0)
	if err := b.Merge([]SignedRow{transfer}); err != nil {
		t.Fatal(err)
	}
	spent := apply(t, b, "at", k["at"], 450, "")
	for i := 0; i < 100; i++ {
		if err := a.Merge([]SignedRow{transfer, spent}); err != nil {
			t.Fatal(err)
		}
	}
	assertBilled(t, a, 450)
	available, _ := a.Available("de", 100)
	if available != 200 {
		t.Fatal(available)
	}
	available, _ = a.Available("at", 100)
	if available != 50 {
		t.Fatal(available)
	}
}
func TestOutOfOrderDependencyIsAtomicThenFullSnapshotRecovers(t *testing.T) {
	p, k := fixture(t)
	a, b := ledger(t, p), ledger(t, p)
	transfer := apply(t, a, "de", k["de"], 200, "at")
	spent := apply(t, a, "at", k["at"], 450, "")
	if err := b.Merge([]SignedRow{spent}); !errors.Is(err, ErrInsufficient) {
		t.Fatal(err)
	}
	assertBilled(t, b, 0)
	if err := b.Merge([]SignedRow{spent, transfer}); err != nil {
		t.Fatal(err)
	}
	assertBilled(t, b, 450)
}
func TestSerializedRestartReplayAndStaleOwnerSnapshot(t *testing.T) {
	p, k := fixture(t)
	a := ledger(t, p)
	old := apply(t, a, "at", k["at"], 100, "")
	apply(t, a, "at", k["at"], 100, "")
	encoded, err := json.Marshal(a.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var persisted []SignedRow
	if err = json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatal(err)
	}
	b := ledger(t, p)
	if err = b.Merge(persisted); err != nil {
		t.Fatal(err)
	}
	if err = b.Merge([]SignedRow{old}); err != nil {
		t.Fatal(err)
	}
	assertBilled(t, b, 200)
}
func TestExpiryAndResetEpochCannotReviveOldRights(t *testing.T) {
	p, k := fixture(t)
	a := ledger(t, p)
	old := apply(t, a, "at", k["at"], 100, "")
	for _, now := range []int64{5000, 1000000000} {
		if _, err := a.Propose("at", k["at"], 1, "", now); !errors.Is(err, ErrInsufficient) {
			t.Fatal(err)
		}
	}
	p.Epoch = "reset-2"
	b := ledger(t, p)
	if err := b.Merge([]SignedRow{old}); !errors.Is(err, ErrEpoch) {
		t.Fatal(err)
	}
	assertBilled(t, b, 0)
}
func TestTamperAndConcurrentWriterConflictRejected(t *testing.T) {
	p, k := fixture(t)
	a := ledger(t, p)
	x, _ := a.Propose("de", k["de"], 100, "at", 100)
	y, _ := a.Propose("de", k["de"], 100, "nl", 100)
	if err := a.Merge([]SignedRow{x}); err != nil {
		t.Fatal(err)
	}
	if err := a.Merge([]SignedRow{y}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	y.Row.Sequence = 2
	if err := a.Merge([]SignedRow{y}); err == nil {
		t.Fatal("tampered row accepted")
	}
	assertBilled(t, a, 0)
}
func TestReservationSurvivesMissingNodeAndCopiesCannotMutateLedger(t *testing.T) {
	p, k := fixture(t)
	a := ledger(t, p)
	apply(t, a, "de", k["de"], 300, "at")
	// Austria disappears. Germany cannot take the transferred bytes back.
	if _, err := a.Propose("de", k["de"], 101, "", 100); !errors.Is(err, ErrInsufficient) {
		t.Fatal(err)
	}
	snapshot := a.Snapshot()
	snapshot[0].Row.Sent["at"] = 0
	if n, _ := a.Available("de", 100); n != 100 {
		t.Fatal(n)
	}
	assertBilled(t, a, 0)
}

func TestRealPollingOverrunIsRecordedOnceAndRepaidBeforeNewTraffic(t *testing.T) {
	p, k := fixture(t)
	a := ledger(t, p)
	r, err := a.Observe("at", k["at"], 320)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err = a.Merge([]SignedRow{r}); err != nil {
			t.Fatal(err)
		}
	}
	assertBilled(t, a, 320)
	if n, _ := a.Available("at", 100); n != 0 {
		t.Fatal(n)
	}
	apply(t, a, "de", k["de"], 50, "at")
	// 20 bytes pay existing debt; only 30 new bytes become available.
	if n, _ := a.Available("at", 100); n != 30 {
		t.Fatal(n)
	}
	r, err = a.Observe("at", k["at"], 320)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Merge([]SignedRow{r}); err != nil {
		t.Fatal(err)
	}
	assertBilled(t, a, 320)
	if n, _ := a.Available("at", 100); n != 30 {
		t.Fatal(n)
	}
	// Delayed actual metering after expiry is still accounted, not discarded.
	r, err = a.Observe("at", k["at"], 350)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Merge([]SignedRow{r}); err != nil {
		t.Fatal(err)
	}
	assertBilled(t, a, 350)
	if n, _ := a.Available("at", 6000); n != 0 {
		t.Fatal(n)
	}
}
