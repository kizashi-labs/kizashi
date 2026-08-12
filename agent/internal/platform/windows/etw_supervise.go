//go:build windows

package windows

import (
	"context"
	"log/slog"
	"sync"
	"time"

	etw "github.com/0xrawsec/golang-etw/etw"
)

// etwSupervisors tracks every running ETW supervisor so shutdown can wait for
// their teardown instead of racing it.
//
// These loops used to be launched as bare `go superviseETWSession(...)`, tracked
// by nothing. The collector's Start() returns as soon as the goroutine is spawned,
// so main's WaitGroup was already satisfied and main returned — killing the
// supervisors mid-teardown. The ETW sessions they own (EDR-Agent-* and the
// singleton "NT Kernel Logger") therefore survived the process, and which ones
// leaked varied run to run, exactly as a race would predict.
//
// Measured on the validation host 2026-08-05: after a clean `Stop-Service`,
// `logman query -ets` still listed NT Kernel Logger plus a different subset of
// EDR-Agent-* sessions on every stop. Every agent restart during that session
// needed a manual `logman stop` first.
var etwSupervisors sync.WaitGroup

// goSuperviseETWSession starts a supervisor and registers it for shutdown.
// Always use this instead of a bare `go superviseETWSession(...)`: the Add must
// happen before the goroutine starts, or WaitETWSupervisors can return before the
// supervisor has even been scheduled.
func goSuperviseETWSession(
	ctx context.Context,
	name string,
	consumer *etw.Consumer,
	establish func(context.Context) (*etw.Consumer, error),
	teardown func(),
) {
	etwSupervisors.Add(1)
	go func() {
		defer etwSupervisors.Done()
		superviseETWSession(ctx, name, consumer, establish, teardown)
	}()
}

// GoSupervised runs fn as a tracked supervisor. For collectors that own a
// bespoke supervise loop (the kernel logger) rather than superviseETWSession.
func GoSupervised(fn func()) {
	etwSupervisors.Add(1)
	go func() {
		defer etwSupervisors.Done()
		fn()
	}()
}

// WaitETWSupervisors blocks until every supervisor has finished tearing its
// session down, or until timeout. Called from the agent's shutdown path AFTER the
// context is cancelled.
//
// Bounded on purpose: a wedged ProcessTrace must not stop the agent from exiting.
// A timeout leaves sessions behind — the very thing this exists to prevent — so it
// is logged loudly, with the recovery command an operator would otherwise have to
// work out from a failed service start.
func WaitETWSupervisors(timeout time.Duration) {
	done := make(chan struct{})
	go func() { etwSupervisors.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("ETWセッションの停止待ちがタイムアウトしました。セッションが残る可能性があります。"+
			"次回起動が失敗する場合は `logman query -ets` で確認し `logman stop <名前> -ets` で停止してください",
			"timeout", timeout.String())
	}
}

// superviseETWSession keeps a named ETW collector's session alive for the life of
// ctx. consumer.Wait() (the consumer's embedded WaitGroup) unblocks when the
// session's ProcessTrace returns — whether from our own teardown or an external
// takeover of the session. golang-etw's RealTimeSession.Start() stops a
// pre-existing same-named trace (ERROR_ALREADY_EXISTS handling), so a second tool
// that opens "EDR-Agent-Registry" (or the singleton kernel logger) silently
// displaces ours and our ProcessTrace returns. Without recovery that permanently
// silences the collector (observed 2026-06-25 for the process collector).
//
// On an unexpected stop it re-establishes after reestablishBackoff via establish;
// on ctx cancel it calls teardown and exits. The collector's Stop() MUST cancel
// ctx so this loop terminates instead of treating the stop as an external death
// and recovering. establish/teardown are only ever called from this single
// goroutine (after the initial establish in startETW), so the collector's
// session/consumer fields need no additional locking.
func superviseETWSession(
	ctx context.Context,
	name string,
	consumer *etw.Consumer,
	establish func(context.Context) (*etw.Consumer, error),
	teardown func(),
) {
	for {
		if consumer == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reestablishBackoff):
			}
			c, err := establish(ctx)
			if err != nil {
				slog.Warn("ETWセッションの再確立に失敗しました。リトライします", "session", name, "error", err)
				continue
			}
			consumer = c
		}

		traceEnded := make(chan struct{})
		cons := consumer
		go func() { cons.Wait(); close(traceEnded) }()

		select {
		case <-ctx.Done():
			teardown()
			return
		case <-traceEnded:
			if ctx.Err() != nil {
				teardown()
				return
			}
			slog.Warn("ETWセッションが外部要因で停止しました。再確立します", "session", name)
			teardown()
			consumer = nil
		}
	}
}
