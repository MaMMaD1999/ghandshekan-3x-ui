package quotaescrow

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSyncTransportPreferenceAndNoStickyEgress(t *testing.T) {
	for _, win := range []string{"direct", "relay", "egress"} {
		var calls []string
		makeAttempt := func(kind string) SyncAttempt {
			return func(ctx context.Context, destination, peer string, rows []SignedRow) error {
				calls = append(calls, kind)
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded network attempt")
				}
				if kind == win {
					return nil
				}
				return errors.New("offline")
			}
		}
		transport := SyncTransport{Direct: makeAttempt("direct"), Relay: makeAttempt("relay"), Egress: makeAttempt("egress")}
		for i := 0; i < 2; i++ {
			calls = nil
			path, err := transport.Sync(context.Background(), "a", []string{"a", "", "b", "b"}, nil)
			if err != nil || path != win {
				t.Fatal(path, err)
			}
			want := map[string][]string{"direct": {"direct"}, "relay": {"direct", "relay"}, "egress": {"direct", "relay", "egress"}}[win]
			if !reflect.DeepEqual(calls, want) {
				t.Fatal(calls, want)
			}
		}
	}
}

func TestSyncTransportCancellationDoesNotEscapeThroughFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := false
	transport := SyncTransport{AttemptTimeout: time.Millisecond, Direct: func(ctx context.Context, _, _ string, _ []SignedRow) error { cancel(); return ctx.Err() }, Egress: func(context.Context, string, string, []SignedRow) error { called = true; return nil }}
	_, err := transport.Sync(ctx, "a", nil, nil)
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled exchange used fallback", err)
	}
}

func TestSyncTransportProtectsSnapshotAndBoundsRelayRetries(t *testing.T) {
	rows := []SignedRow{{Row: Row{Sequence: 7, Sent: map[string]int64{"b": 5}}}}
	count := 0
	transport := SyncTransport{MaxRelays: 2, Direct: func(_ context.Context, _, _ string, r []SignedRow) error {
		r[0].Row.Sent["b"] = 999
		return errors.New("lost ACK")
	}, Relay: func(_ context.Context, _, _ string, r []SignedRow) error {
		count++
		if r[0].Row.Sent["b"] != 5 {
			t.Fatal("mutated retry")
		}
		return errors.New("offline")
	}}
	_, err := transport.Sync(context.Background(), "a", []string{"b", "c", "d"}, rows)
	if err == nil || count != 2 || rows[0].Row.Sent["b"] != 5 {
		t.Fatal("unbounded or mutated exchange")
	}
}
