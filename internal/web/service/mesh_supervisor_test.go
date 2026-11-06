package service

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeshSupervisorNetworkFailureDoesNotDelayLocalEnforcement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var cycles atomic.Int32
	s := MeshSupervisor{
		LocalInterval: time.Millisecond, ExchangeInterval: time.Millisecond,
		Local: func(context.Context) error {
			if cycles.Add(1) == 5 {
				cancel()
			}
			return errors.New("already fenced settlement failure")
		},
		Exchange:      func(c context.Context) error { <-c.Done(); return c.Err() },
		EmergencyStop: func(error) error { t.Error("ordinary failure stopped entire runtime"); return nil },
	}
	if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if cycles.Load() != 5 {
		t.Fatal("peer outage delayed local enforcement", cycles.Load())
	}
}

func TestMeshSupervisorStopsOnUnconfirmedFenceOrPanic(t *testing.T) {
	for _, panicWorker := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var stopped atomic.Int32
		s := MeshSupervisor{
			LocalInterval: time.Millisecond, ExchangeInterval: time.Millisecond,
			Local: func(context.Context) error {
				if panicWorker {
					panic("broken worker")
				}
				return &MeshFenceError{Err: errors.New("core RPC unavailable")}
			},
			Exchange:      func(c context.Context) error { <-c.Done(); return c.Err() },
			EmergencyStop: func(error) error { stopped.Add(1); return nil },
		}
		err := s.Run(ctx)
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) || stopped.Load() != 1 {
			t.Fatal(err, stopped.Load())
		}
		if panicWorker && !strings.Contains(err.Error(), "worker panic") {
			t.Fatal(err)
		}
	}
}
