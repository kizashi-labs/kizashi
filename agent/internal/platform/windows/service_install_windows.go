//go:build windows

package windows

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	v1 "github.com/edr-platform/proto/agent/v1"
	winsys "golang.org/x/sys/windows"
)

// WindowsServiceInstallCollector detects Windows service installation — System
// EventID 7045 ("A service was installed in the system") — and emits a
// service_installed finding. Installing a service is the classic PsExec /
// Cobalt Strike lateral-movement + persistence primitive (T1543.003); the
// server flags the malicious ones by ImagePath shape. It had no sensor, so
// service-based lateral movement was invisible. Read-only over the System log
// (readable without admin), polling every 15s.
type WindowsServiceInstallCollector struct {
	cancel    context.CancelFunc
	agentID   string
	sender    collector.EventSender
	watermark *collector.EventLogWatermark
}

// NewWindowsServiceInstallCollector creates the service-install collector.
func NewWindowsServiceInstallCollector() *WindowsServiceInstallCollector {
	return &WindowsServiceInstallCollector{}
}

// Start begins polling in a background goroutine. Returns nil immediately.
func (c *WindowsServiceInstallCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	if sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.agentID = agentID
	c.sender = sender
	c.watermark = collector.NewEventLogWatermark(time.Now().Add(-60 * time.Second))
	slog.Info("サービスインストールの監視を開始します (System 7045)")
	go c.run(ctx)
	return nil
}

// Stop cancels the polling goroutine.
func (c *WindowsServiceInstallCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *WindowsServiceInstallCollector) run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		events, err := c.query()
		if err != nil {
			continue // channel access error — skip quietly
		}
		for _, batch := range events {
			if err := c.sender.SendEvents(ctx, batch); err != nil {
				slog.Debug("[service_installed] イベント送信失敗", "error", err)
			}
		}
	}
}

func (c *WindowsServiceInstallCollector) query() ([]*v1.EventBatch, error) {
	round := c.watermark.BeginRound()
	timeStr := c.watermark.QueryFrom().UTC().Format("2006-01-02T15:04:05.000Z")
	var newest time.Time
	q := fmt.Sprintf(`*[System[(EventID=7045) and TimeCreated[@SystemTime>='%s']]]`, timeStr)

	channelPtr, err := winsys.UTF16PtrFromString("System")
	if err != nil {
		return nil, err
	}
	queryPtr, err := winsys.UTF16PtrFromString(q)
	if err != nil {
		return nil, err
	}
	hQuery, _, callErr := procEvtQuery.Call(
		0, uintptr(unsafe.Pointer(channelPtr)), uintptr(unsafe.Pointer(queryPtr)), evtQueryChannelPath,
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery(System) failed: %w", callErr)
	}
	defer procEvtClose.Call(hQuery)

	var out []*v1.EventBatch
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
			f, ts, ok := parseServiceInstall(xmlStr)
			if !ok {
				continue
			}
			// The XPath lower bound is inclusive, so the newest already-reported
			// 7045 comes back on EVERY poll. Emitting it again turned one Defender
			// service install into 5,761 events and a [PERSIST] alert every five
			// minutes. Fetch it, then drop it here.
			if !c.watermark.ShouldEmit(round, ts) {
				continue
			}
			if ts.After(newest) {
				newest = ts
			}
			payload := collector.ServiceInstallPayload(f.name, f.imagePath, f.serviceType, f.startType, f.account)
			if batch := collector.BuildServiceInstallEvent(c.agentID, payload); batch != nil {
				out = append(out, batch)
			}
		}
	}
	c.watermark.Commit(newest)
	return out, nil
}

// svcInstallFields holds the parsed EID 7045 EventData values.
type svcInstallFields struct {
	name, imagePath, serviceType, startType, account string
}

// parseServiceInstall extracts the EID 7045 fields from a rendered event XML.
// EID 7045 uses the standard <EventData> schema with ServiceName / ImagePath /
// ServiceType / StartType / AccountName.
func parseServiceInstall(xmlStr string) (svcInstallFields, time.Time, bool) {
	xmlStr = strings.Replace(xmlStr,
		` xmlns='http://schemas.microsoft.com/win/2004/08/events/event'`, "", 1)
	var raw winEventXML
	if err := xml.Unmarshal([]byte(xmlStr), &raw); err != nil {
		return svcInstallFields{}, time.Time{}, false
	}
	if raw.System.EventID != 7045 {
		return svcInstallFields{}, time.Time{}, false
	}
	data := make(map[string]string, len(raw.EventData.Data))
	for _, d := range raw.EventData.Data {
		data[d.Name] = d.Value
	}
	ts, err := time.Parse("2006-01-02T15:04:05.000000000Z", raw.System.TimeCreated.SystemTime)
	if err != nil {
		if ts, err = time.Parse("2006-01-02T15:04:05Z", raw.System.TimeCreated.SystemTime); err != nil {
			ts = time.Now()
		}
	}
	return svcInstallFields{
		name:        data["ServiceName"],
		imagePath:   data["ImagePath"],
		serviceType: data["ServiceType"],
		startType:   data["StartType"],
		account:     data["AccountName"],
	}, ts, true
}
