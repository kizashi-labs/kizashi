//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"syscall"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	winsys "golang.org/x/sys/windows"
)

var (
	modWevtapi       = winsys.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery     = modWevtapi.NewProc("EvtQuery")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modWevtapi.NewProc("EvtNext")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")

	// syscall.Proc.Call always hands back GetLastError, success or failure. When a
	// Win32 call returns FALSE without setting an error code, we would otherwise
	// read whatever the previous call on this thread left behind and report it as
	// the cause — instrumentation that cries wolf. Zero it first so the errno we
	// log is genuinely EvtNext's.
	modKernel32      = winsys.NewLazySystemDLL("kernel32.dll")
	procSetLastError = modKernel32.NewProc("SetLastError")
)

const (
	evtQueryChannelPath        = 0x1
	evtRenderEventXml          = 1
	evtSubscribeToFutureEvents = 1

	// EvtNext returns FALSE for both of these, and they mean opposite things.
	// Conflating them is what stranded every subscribed auth event: see drain().
	errorNoMoreItems = 259  // ERROR_NO_MORE_ITEMS — batch exhausted (normal)
	errorTimeout     = 1460 // ERROR_TIMEOUT — pending, not yet materialised
	// ERROR_INVALID_OPERATION is how a SUBSCRIPTION handle reports "nothing
	// available right now" — it is the normal empty result here, not a fault.
	// Established on the validation host 2026-08-05: it appears on the first sweep
	// over an idle subscription, survives SetLastError(0) (so it is genuinely
	// EvtNext's), and events continue to be delivered normally afterwards. Logging
	// it as a failure was the instrumentation crying wolf.
	errorInvalidOperation = 4317

	// evtNextTimeoutMS stays 0: draining is driven by the signal event plus the
	// periodic sweep in consumeSubscription, not by blocking inside EvtNext.
	//
	// A 200ms value was tried on the validation host first, on the theory that
	// Timeout=0 was stranding events. It was NOT the cause — the same
	// ERROR_INVALID_OPERATION appeared at 0 — and the A/B showed the sweep alone
	// restores delivery. Recorded so the timeout is not "fixed" again.
	evtNextTimeoutMS = 0

	// authSubscribeReportEvery rate-limits the drain-failure log and drives the
	// periodic "subscribed but delivering nothing" report.
	authSubscribeReportEvery = 5 * time.Minute

	// authSubscribeSweepEvery is how often the loop drains even without a signal,
	// so a batch the auto-reset signal already consumed cannot be stranded.
	authSubscribeSweepEvery = 2 * time.Second
)

// WindowsAuthCollector monitors authentication events via the Windows Security Event Log.
// It polls every 10 seconds and filters for logon (4624), failed logon (4625),
// logoff (4634), privilege escalation (4672), and explicit-credential logon (4648).
type WindowsAuthCollector struct {
	cancel context.CancelFunc
	// failures counts consecutive query failures so the warning is logged on the
	// first one and then only periodically, rather than every 10s forever.
	failures int
	// lastLogged rate-limits per-stage drain failures (see logOnce). Only touched
	// from the single consumeSubscription goroutine.
	lastLogged map[string]time.Time
}

// logQueryFailure surfaces a Security-log read failure without flooding the log:
// the first failure and then roughly every 5 minutes (30 polls at 10s).
func (c *WindowsAuthCollector) logQueryFailure(err error) {
	c.failures++
	if c.failures == 1 || c.failures%30 == 0 {
		slog.Warn("Securityイベントログを読めません。認証イベント(4625等)が収集されず、"+
			"ブルートフォース検知(T1110)が機能しません。管理者権限と監査ポリシを確認してください",
			"error", err, "連続失敗回数", c.failures)
	}
}

// NewWindowsAuthCollector creates a new Windows authentication event collector.
func NewWindowsAuthCollector() *WindowsAuthCollector {
	return &WindowsAuthCollector{}
}

// Start begins collecting auth events. With EDR_AGENT_ETW opted in, the Security
// log is consumed in real time via EvtSubscribe (push), instead of the default
// 10s polling — failed-logon bursts and lateral-movement logons are surfaced
// immediately. Any failure falls back to polling.
func (c *WindowsAuthCollector) Start(ctx context.Context, out chan<- collector.AuthEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	if etwEnabled() {
		if err := c.subscribe(ctx, out); err != nil {
			slog.Warn("認証イベントのEvtSubscribe購読を開始できませんでした。ポーリングにフォールバックします", "error", err)
		} else {
			slog.Info("認証イベントをEvtSubscribeでリアルタイム購読します (Security)")
			return nil
		}
	}
	go c.run(ctx, out)
	return nil
}

// subscribe registers a push subscription on the Security channel. New matching
// events signal an auto-reset event object, which a goroutine waits on and then
// drains via EvtNext. Returns an error so the caller can fall back to polling.
func (c *WindowsAuthCollector) subscribe(ctx context.Context, out chan<- collector.AuthEvent) error {
	signalEvent, err := winsys.CreateEvent(nil, 0, 0, nil) // auto-reset, non-signaled
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}

	channelPtr, err := winsys.UTF16PtrFromString("Security")
	if err != nil {
		winsys.CloseHandle(signalEvent)
		return err
	}
	queryPtr, err := winsys.UTF16PtrFromString(buildAuthSubscribeQuery())
	if err != nil {
		winsys.CloseHandle(signalEvent)
		return err
	}

	hSub, _, callErr := procEvtSubscribe.Call(
		0,                                   // Session: NULL (local)
		uintptr(signalEvent),                // SignalEvent
		uintptr(unsafe.Pointer(channelPtr)), // ChannelPath
		uintptr(unsafe.Pointer(queryPtr)),   // Query
		0,                                   // Bookmark
		0,                                   // Context
		0,                                   // Callback (NULL → signal mode)
		evtSubscribeToFutureEvents,          // Flags
	)
	if hSub == 0 {
		winsys.CloseHandle(signalEvent)
		return fmt.Errorf("EvtSubscribe failed: %w (管理者権限が必要です)", callErr)
	}

	go c.consumeSubscription(ctx, hSub, signalEvent, out)
	return nil
}

// consumeSubscription waits on the signal event and drains new auth events.
//
// Every failure in this loop used to be a bare `continue`/`break`, so a
// systematically failing drain was indistinguishable from an idle host: the
// subscription logged "購読します" once and then produced nothing, forever. That
// is exactly what shipped — 2026-08-05 measurement, Security log holding real
// 4625s while the server received ZERO auth events, and not one line to say why.
// T1110 cannot fire without this input, so the silence was the whole bug.
func (c *WindowsAuthCollector) consumeSubscription(ctx context.Context, hSub uintptr, signalEvent winsys.Handle, out chan<- collector.AuthEvent) {
	defer winsys.CloseHandle(signalEvent)
	defer procEvtClose.Call(hSub)

	handles := make([]uintptr, 32)
	var delivered, renderFail, parseFail uint64
	lastSweep := time.Now()
	lastReport := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Wait up to 1s so ctx cancellation is observed promptly.
		// WAIT_OBJECT_0 (0) = signaled; anything else (e.g. WAIT_TIMEOUT) → re-loop.
		signaled := false
		if w, _ := winsys.WaitForSingleObject(signalEvent, 1000); w == 0 {
			signaled = true
		}

		// Drain on the signal, and also on a periodic sweep. The signal event is
		// AUTO-RESET, so the wait above consumes it: if EvtNext then declines to hand
		// over the batch (ERROR_TIMEOUT — see drain), those events are stranded until
		// some *later* event re-signals, and that pass hits the same race. The sweep
		// makes the loop self-healing rather than dependent on a lucky signal.
		if signaled || time.Since(lastSweep) >= authSubscribeSweepEvery {
			lastSweep = time.Now()
			c.drain(ctx, hSub, handles, out, &delivered, &renderFail, &parseFail)
		}

		// A subscription that is up but has handed over nothing is precisely the
		// failure mode this collector shipped with. Say so, rather than looking
		// healthy. (Rendering/parsing losses are reported whenever they occur.)
		// Per-call noise is deliberately silent (see logDrainStop): the empty-result
		// codes are indistinguishable from a healthy idle host. The alarm that
		// matters is at the OUTCOME level — a subscription that has been up for a
		// full report interval and handed over nothing at all. That is the exact
		// state this collector shipped in, and it is what must never be quiet again.
		if time.Since(lastReport) >= authSubscribeReportEvery {
			lastReport = time.Now()
			switch {
			case delivered == 0:
				slog.Warn("認証イベントを購読中ですが、この間 1 件も配送されていません。"+
					"Security ログに 4624/4625 が出ているか、監査ポリシ(Logon: Success and Failure)を確認してください。"+
					"ブルートフォース検知(T1110)はこの入力が無ければ発火しません",
					"経過", authSubscribeReportEvery.String(),
					"レンダリング失敗", renderFail, "パース失敗", parseFail)
			case renderFail > 0:
				slog.Warn("認証イベントの購読で取りこぼしが発生しています",
					"配送", delivered, "レンダリング失敗", renderFail, "パース失敗", parseFail)
			}
		}
	}
}

// drain pulls every currently-available event out of the subscription.
func (c *WindowsAuthCollector) drain(
	ctx context.Context, hSub uintptr, handles []uintptr,
	out chan<- collector.AuthEvent, delivered, renderFail, parseFail *uint64,
) {
	for {
		var returned uint32
		// EvtNext returns FALSE both for ERROR_NO_MORE_ITEMS (the batch is genuinely
		// exhausted) and for other conditions that are NOT "nothing left". The
		// original code read only the boolean and treated every FALSE as the former,
		// so a batch the signal had just announced could be abandoned — and because
		// the signal event is auto-reset and already consumed, nothing re-drained it.
		procSetLastError.Call(0)
		ret, _, callErr := procEvtNext.Call(
			hSub,
			uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])),
			evtNextTimeoutMS,
			0, // flags
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			c.logDrainStop(callErr)
			return
		}
		for i := uint32(0); i < returned; i++ {
			h := handles[i]
			xmlStr, err := evtRenderXML(h)
			procEvtClose.Call(h)
			if err != nil {
				*renderFail++
				c.logOnce("evtRender", err)
				continue
			}
			evt, err := parseAuthEvent(xmlStr)
			if err != nil {
				// Not every miss is a defect: 4624/4634 for SYSTEM and the other
				// service accounts are skipped on purpose (parseAuthEvent), and an
				// event ID outside our five is filtered too. Counted, not logged.
				*parseFail++
				continue
			}
			select {
			case out <- evt:
				*delivered++
			case <-ctx.Done():
				return
			}
		}
	}
}

// logDrainStop reports why a drain ended. ERROR_NO_MORE_ITEMS is the normal exit
// and stays silent; anything else means the subscription is not delivering and
// must not look the same as an idle host.
func (c *WindowsAuthCollector) logDrainStop(callErr error) {
	errno, ok := callErr.(syscall.Errno)
	if !ok || errno == 0 {
		return
	}
	switch uintptr(errno) {
	case errorNoMoreItems, errorInvalidOperation:
		// Normal "nothing left / nothing yet" for a subscription handle.
		return
	case errorTimeout:
		// Pending-but-not-ready; the sweep re-drains.
		return
	}
	c.logOnce("evtNext", callErr)
}

// logOnce rate-limits a repeating failure to the first occurrence and then one
// every authSubscribeReportEvery, mirroring logQueryFailure's contract: a
// collector that cannot read its source must say so, without flooding the log.
func (c *WindowsAuthCollector) logOnce(stage string, err error) {
	now := time.Now()
	if last, seen := c.lastLogged[stage]; seen && now.Sub(last) < authSubscribeReportEvery {
		return
	}
	if c.lastLogged == nil {
		c.lastLogged = make(map[string]time.Time)
	}
	c.lastLogged[stage] = now
	slog.Warn("認証イベントの購読処理に失敗しました。ブルートフォース検知(T1110)の入力が欠落します",
		"段階", stage, "error", err)
}

func (c *WindowsAuthCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *WindowsAuthCollector) run(ctx context.Context, out chan<- collector.AuthEvent) {
	// Capture events from the past minute on startup, then track last-seen time.
	lastSeen := time.Now().Add(-60 * time.Second)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := c.queryAuthEvents(lastSeen)
			if err != nil {
				// NEVER skip quietly. This used to `continue` with no log line, and a
				// malformed time predicate in the query made every poll fail — the agent
				// shipped ZERO auth events for the product's lifetime with nothing to
				// show for it, leaving T1110 brute-force detection with no input at all.
				// A collector that cannot read its source must say so.
				c.logQueryFailure(err)
				continue
			}
			c.failures = 0
			for _, evt := range events {
				if evt.Timestamp.After(lastSeen) {
					lastSeen = evt.Timestamp
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (c *WindowsAuthCollector) queryAuthEvents(since time.Time) ([]collector.AuthEvent, error) {
	// Window back to `since`, plus a margin for poll jitter and clock skew.
	// Windows only supports timediff() for time filtering — see buildAuthQuery.
	query := buildAuthQuery(time.Since(since).Milliseconds() + 2000)

	channelPtr, err := winsys.UTF16PtrFromString("Security")
	if err != nil {
		return nil, err
	}
	queryPtr, err := winsys.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}

	hQuery, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		evtQueryChannelPath,
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery failed: %w", callErr)
	}
	defer procEvtClose.Call(hQuery)

	var results []collector.AuthEvent
	handles := make([]uintptr, 32)

	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			hQuery,
			uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])),
			0, // timeout: return immediately if no more events
			0, // flags: reserved
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			break // ERROR_NO_MORE_ITEMS or error
		}

		for i := uint32(0); i < returned; i++ {
			h := handles[i]
			xmlStr, err := evtRenderXML(h)
			procEvtClose.Call(h)
			if err != nil {
				continue
			}
			evt, err := parseAuthEvent(xmlStr)
			if err != nil {
				continue
			}
			results = append(results, evt)
		}
	}

	return results, nil
}

// evtRenderXML renders a Windows event handle as an XML string.
func evtRenderXML(hEvent uintptr) (string, error) {
	// Try with a 16 KB buffer; resize to 128 KB if needed.
	buf := make([]uint16, 8192)
	var bufUsed, propCount uint32

	ret, _, _ := procEvtRender.Call(
		0, // context: NULL for XML rendering
		hEvent,
		evtRenderEventXml,
		uintptr(uint32(len(buf)*2)), // buffer size in bytes
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		// Resize and retry
		buf = make([]uint16, 65536)
		ret, _, err := procEvtRender.Call(
			0, hEvent, evtRenderEventXml,
			uintptr(uint32(len(buf)*2)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		if ret == 0 {
			return "", fmt.Errorf("EvtRender: %w", err)
		}
	}

	n := bufUsed / 2
	if n == 0 || n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	return winsys.UTF16ToString(buf[:n]), nil
}
