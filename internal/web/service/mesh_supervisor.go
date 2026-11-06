package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

// MeshSupervisor separates local enforcement from bounded peer exchanges.
// EmergencyStop must synchronously stop runtime admission and active streams;
// it is called when a local cycle panics or cannot confirm its runtime fence.
// Reporting ordinary peer failures cannot mint rights or pause local metering.
type MeshSupervisor struct {
	Local            func(context.Context) error
	Exchange         func(context.Context) error
	EmergencyStop    func(error) error
	Report           func(string, error)
	LocalInterval    time.Duration
	ExchangeInterval time.Duration
}

func (s MeshSupervisor) Run(ctx context.Context) error {
	if s.Local == nil || s.Exchange == nil || s.EmergencyStop == nil || s.LocalInterval <= 0 || s.ExchangeInterval <= 0 {
		return errors.New("invalid mesh supervisor configuration")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var fatal error
	var fatalMu sync.Mutex
	report := func(kind string, err error) {
		if err != nil && s.Report != nil {
			s.Report(kind, err)
		}
	}
	stop := func(err error) {
		fatalMu.Lock()
		defer fatalMu.Unlock()
		if fatal == nil {
			fatal = err
			cancel()
			stopErr := func() (failure error) {
				defer func() {
					if v := recover(); v != nil {
						failure = fmt.Errorf("mesh emergency stop panic: %v", v)
					}
				}()
				return s.EmergencyStop(err)
			}()
			fatal = errors.Join(fatal, stopErr)
		}
	}
	for _, spec := range []struct {
		kind     string
		interval time.Duration
		cycle    func(context.Context) error
	}{
		{"local", s.LocalInterval, s.Local}, {"exchange", s.ExchangeInterval, s.Exchange},
	} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				if v := recover(); v != nil {
					// Losing the gossip worker silently is unsafe too: the process
					// must expose failure rather than look like a healthy mesh.
					stop(fmt.Errorf("mesh %s worker panic: %v", spec.kind, v))
				}
			}()
			_ = quotaescrow.RunSync(child, spec.interval, func(c context.Context) {
				err := spec.cycle(c)
				if child.Err() != nil {
					return
				}
				var fence *MeshFenceError
				if spec.kind == "local" && errors.As(err, &fence) {
					stop(err)
					return
				}
				report(spec.kind, err)
			})
		}()
	}
	workers.Wait()
	if fatal != nil {
		return fatal
	}
	return ctx.Err()
}
