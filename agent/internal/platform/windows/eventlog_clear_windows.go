//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	winsys "golang.org/x/sys/windows"
)

// WindowsEventLogClearCollector detects Windows audit-log clearing — Security
// EventID 1102 ("the audit log was cleared") and System EventID 104 ("the log
// file was cleared") — and emits an eventlog_cleared finding. Clearing the log
// is a high-signal defense-evasion move (T1070.001) that destroys the very
// telemetry the rest of the pipeline relies on; it previously had no sensor, so
// a wipe was invisible. Read-only over the event log (needs Security-channel
// read access, i.e. Administrator); it polls every 15s and tracks last-seen.
type WindowsEventLogClearCollector struct {
	cancel  context.CancelFunc
	agentID string
	sender  collector.EventSender
}

// NewWindowsEventLogClearCollector creates the audit-log-clear collector.
func NewWindowsEventLogClearCollector() *WindowsEventLogClearCollector {
	return &WindowsEventLogClearCollector{}
}

// Start begins polling in a background goroutine. Returns nil immediately; if the
// Security channel can't be read (non-admin) the queries fail quietly and the
// collector is effectively a no-op.
func (c *WindowsEventLogClearCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	if sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.agentID = agentID
	c.sender = sender
	slog.Info("イベントログ消去の監視を開始します (Security 1102 / System 104)")
	go c.run(ctx)
	return nil
}

// Stop cancels the polling goroutine.
func (c *WindowsEventLogClearCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

type clearWatch struct {
	channel   string
	eventID   int
	watermark *collector.EventLogWatermark
}

func (c *WindowsEventLogClearCollector) run(ctx context.Context) {
	start := time.Now().Add(-60 * time.Second)
	watches := []*clearWatch{
		{channel: "Security", eventID: 1102, watermark: collector.NewEventLogWatermark(start)},
		{channel: "System", eventID: 104, watermark: collector.NewEventLogWatermark(start)},
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, w := range watches {
			events, err := c.queryClears(w)
			if err != nil {
				continue // channel access denied (non-admin) — skip quietly
			}
			round := w.watermark.BeginRound()
			var newest time.Time
			for _, ev := range events {
				// Same inclusive-boundary re-match as the 7045 collector. Untriggered
				// here only because nobody had cleared a log — and a log clear
				// (T1070.001) turning into an unending alert stream would be the
				// worst possible place for this bug to surface.
				if !w.watermark.ShouldEmit(round, ev.when) {
					continue
				}
				if ev.when.After(newest) {
					newest = ev.when
				}
				batch := collector.BuildEventLogClearEvent(c.agentID,
					collector.EventLogClearPayload(w.channel, ev.user, ev.backupPath))
				if batch == nil {
					continue
				}
				if err := c.sender.SendEvents(ctx, batch); err != nil {
					slog.Debug("[eventlog_cleared] イベント送信失敗", "error", err)
				}
			}
			w.watermark.Commit(newest)
		}
	}
}

type clearEvent struct {
	when       time.Time
	user       string
	backupPath string
}

func (c *WindowsEventLogClearCollector) queryClears(w *clearWatch) ([]clearEvent, error) {
	timeStr := w.watermark.QueryFrom().UTC().Format("2006-01-02T15:04:05.000Z")
	query := fmt.Sprintf(`*[System[(EventID=%d) and TimeCreated[@SystemTime>='%s']]]`, w.eventID, timeStr)

	channelPtr, err := winsys.UTF16PtrFromString(w.channel)
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
		return nil, fmt.Errorf("EvtQuery(%s) failed: %w", w.channel, callErr)
	}
	defer procEvtClose.Call(hQuery)

	var results []clearEvent
	handles := make([]uintptr, 32)
	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			hQuery, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])),
			0, 0, uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			break
		}
		for i := uint32(0); i < returned; i++ {
			h := handles[i]
			xmlStr, err := evtRenderXML(h)
			procEvtClose.Call(h)
			if err != nil {
				continue
			}
			results = append(results, parseEventLogClear(xmlStr))
		}
	}
	return results, nil
}

// EID 1102 (Security) and 104 (System) carry the clearing account under
// <UserData> rather than <EventData>, and the element schema differs between
// them. Rather than model both, extract the load-bearing fields with tolerant
// regexes — the finding fires on the query match alone, so user/backup are
// best-effort context. SystemTime is on the <TimeCreated> element.
var (
	reClearUser    = regexp.MustCompile(`<SubjectUserName>([^<]*)</SubjectUserName>`)
	reClearBackup  = regexp.MustCompile(`<BackupPath>([^<]*)</BackupPath>`)
	reClearSysTime = regexp.MustCompile(`SystemTime=['"]([^'"]+)['"]`)
)

func parseEventLogClear(xmlStr string) clearEvent {
	ev := clearEvent{when: time.Now()}
	if m := reClearUser.FindStringSubmatch(xmlStr); m != nil {
		ev.user = m[1]
	}
	if m := reClearBackup.FindStringSubmatch(xmlStr); m != nil {
		ev.backupPath = m[1]
	}
	if m := reClearSysTime.FindStringSubmatch(xmlStr); m != nil {
		if t, err := time.Parse("2006-01-02T15:04:05.000000000Z", m[1]); err == nil {
			ev.when = t
		} else if t, err := time.Parse("2006-01-02T15:04:05Z", m[1]); err == nil {
			ev.when = t
		}
	}
	return ev
}
