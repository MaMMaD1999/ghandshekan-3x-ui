package meshconsensus

import (
	"context"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/quotaescrow"
)

func TestScheduledResetIsCommittedOnceAndRejectsFutureBoundaries(t *testing.T) {
	c := cluster(t, 3)
	n := c.leader(c.ids())
	p := c.base()
	p.ResetSchedule = &quotaescrow.ResetSchedule{Zone: "UTC", StartedAt: time.Now().Add(-3 * time.Hour).Unix(), Hourly: true}
	r, err := SignRegistration(p, c.authority)
	if err != nil {
		t.Fatal(err)
	}
	execute(t, n, Command{ID: "register-schedule", Registration: &r})
	page := n.FSM.SchedulePage("", 16)
	if len(page) != 1 || page[0].Subscription != p.Subscription || len(n.FSM.SchedulePage(p.Subscription, 16)) != 0 {
		t.Fatal("schedule page omitted or repeated policy", page)
	}
	at, err := p.ResetSchedule.Due(time.Now(), 0)
	if err != nil || at == 0 {
		t.Fatal(at, err)
	}
	command := Command{ID: ScheduledOperationID(p.Subscription, at), Subscription: p.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: at}}
	a := execute(t, n, command)
	b := execute(t, n, command)
	if a.Update.Next.Version != 2 || b.Update.Next.Version != 2 || b.Update.Next.ResetGeneration != 2 || b.Update.Next.ScheduledThrough != at {
		t.Fatal("duplicate scheduled reset")
	}
	for _, bad := range []Command{
		{ID: "duplicate-period", Subscription: p.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: at}},
		{ID: "future-period", Subscription: p.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: at + 7200}},
		{ID: "not-a-boundary", Subscription: p.Subscription, Kind: "scheduled-reset", Patch: &PolicyPatch{ScheduledAt: at + 1}},
		{ID: "sneak-into-renew", Subscription: p.Subscription, Kind: "renew", Patch: &PolicyPatch{ScheduledAt: at}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := n.Execute(ctx, bad)
		cancel()
		if err == nil {
			t.Fatal("invalid schedule operation accepted", bad.ID)
		}
	}
	current, _ := n.FSM.Policy(p.Subscription)
	if current.Version != 2 || current.ResetGeneration != 2 {
		t.Fatal("rejected operation changed policy")
	}
}

func TestManualResetCoversOverduePeriodBeforeClearingUsage(t *testing.T) {
	c := cluster(t, 3)
	n := c.leader(c.ids())
	p := c.base()
	p.ResetSchedule = &quotaescrow.ResetSchedule{Zone: "UTC", StartedAt: time.Now().Add(-3 * time.Hour).Unix(), Hourly: true}
	r, _ := SignRegistration(p, c.authority)
	execute(t, n, Command{ID: "register-manual-schedule", Registration: &r})
	at, _ := p.ResetSchedule.Due(time.Now(), 0)
	manual := Command{ID: "reset-before-timer-worker", Subscription: p.Subscription, Kind: "reset", Patch: &PolicyPatch{}}
	result := execute(t, n, manual)
	if result.Update.Next.Version != 3 || result.Update.Next.ResetGeneration != 3 || result.Update.Next.ScheduledThrough != at {
		t.Fatal("overdue period remained after manual reset")
	}
	if due, err := p.ResetSchedule.Due(time.Now(), result.Update.Next.ScheduledThrough); err != nil || due != 0 {
		t.Fatal("scheduler would clear new usage again", due, err)
	}
	replay := execute(t, n, manual)
	if !quotaescrow.SamePolicyUpdate(*replay.Update, *result.Update) {
		t.Fatal("manual retry applied another reset")
	}
}
