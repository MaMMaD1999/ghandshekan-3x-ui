package meshconsensus

import (
	"path/filepath"
	"testing"

	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestAttestationJournalRejectsConflictingRestoredVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "independent-votes.db")
	store, err := raftboltdb.NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	guard := &attestationGuard{store: store}
	committed := quotaescrow.PolicyUpdate{ID: "accepted-reset", Kind: "reset", PreviousHash: "previous", Next: quotaescrow.Policy{ControlEpoch: "cluster", Subscription: "subscriber", Version: 4, ResetGeneration: 2, Limit: 100}}
	if err := guard.remember(committed); err != nil {
		t.Fatal(err)
	}
	guard.close()
	store, err = raftboltdb.NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	guard = &attestationGuard{store: store}
	defer guard.close()
	if err := guard.remember(committed); err != nil {
		t.Fatal("exact committed replay", err)
	}
	conflicting := copyJSON(committed)
	conflicting.ID = "restored-fork"
	conflicting.Next.Limit = 1000
	if err := guard.remember(conflicting); err == nil {
		t.Fatal("an old restored control DB can now double-sign this version")
	}
	next := copyJSON(committed)
	next.ID = "next-renewal"
	next.Kind = "renew"
	next.Next.Version++
	if err := guard.remember(next); err != nil {
		t.Fatal("next committed version", err)
	}
	if err := guard.remember(committed); err != nil {
		t.Fatal("historical catch-up certificate", err)
	}
}
