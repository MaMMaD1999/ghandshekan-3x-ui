//go:build cgo

package quotaescrow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoverySkipsCompletedAndUnreachableJobCannotStarveOthers(t *testing.T) {
	store, close := openStore(t, filepath.Join(t.TempDir(), "recovery.sqlite"))
	defer close()
	db := store.db
	if err := db.AutoMigrate(&ControlJob{}); err != nil {
		t.Fatal(err)
	}
	for _, job := range []ControlJob{{ID: "a-down"}, {ID: "b-complete", Complete: true}, {ID: "c-ready"}, {ID: "d-ready"}} {
		if err := db.Create(&job).Error; err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	resume := func(ctx context.Context, id string) (bool, error) {
		calls = append(calls, id)
		if id == "a-down" {
			<-ctx.Done()
			return false, ctx.Err()
		}
		return true, db.Model(&ControlJob{}).Where("id = ?", id).Update("complete", true).Error
	}
	cursor, results, err := recoverPending(context.Background(), db, "", 2, 10*time.Millisecond, resume)
	if err != nil || cursor != "c-ready" || len(results) != 2 || results[0].Complete || !results[1].Complete {
		t.Fatal(cursor, results, err)
	}
	cursor, results, err = recoverPending(context.Background(), db, cursor, 2, time.Second, resume)
	if err != nil || cursor != "d-ready" || len(results) != 1 || !results[0].Complete {
		t.Fatal(cursor, results, err)
	}
	cursor, results, err = recoverPending(context.Background(), db, cursor, 2, time.Second, resume)
	if err != nil || cursor != "" || len(results) != 0 {
		t.Fatal(cursor, results, err)
	}
	_, results, err = recoverPending(context.Background(), db, cursor, 2, 10*time.Millisecond, resume)
	if err != nil || len(results) != 1 || results[0].Operation != "a-down" || len(calls) != 4 {
		t.Fatal(calls, results, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := recoverPending(ctx, db, "", 2, time.Second, resume); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
