//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
)

const (
	// remoteThreadSessionName is a dedicated ETW session for cross-process thread
	// creation on the Kernel-Process provider with the THREAD keyword enabled.
	remoteThreadSessionName = "EDR-Agent-RemoteThread"
	// etwThreadStartID is the Kernel-Process ThreadStart event (id 3), emitted when
	// the THREAD keyword (0x2) is enabled on the provider.
	etwThreadStartID        = 3
	keywordThread    uint64 = 0x2 // WINEVENT_KEYWORD_THREAD
)

// ETWRemoteThreadCollector detects CreateRemoteThread-style process injection
// (T1055.012) via ETW. For a Kernel-Process ThreadStart the event-header PID is
// the CREATOR (the thread calling NtCreateThreadEx) while the payload ProcessID
// is the TARGET the thread runs in. When they differ AND the creator runs from a
// user-writable location (injectors do; the normal thread-creators csrss/services/
// the process itself live under %SystemRoot%), it is emitted as a
// create_remote_thread finding for the "Process Hollowing" SigmaHQ rule.
type ETWRemoteThreadCollector struct {
	cancel      context.CancelFunc
	agentID     string
	sender      collector.EventSender
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWRemoteThreadCollector() *ETWRemoteThreadCollector {
	return &ETWRemoteThreadCollector{}
}

// Start begins ETW remote-thread monitoring. Additive sensor: default ON,
// opt-out via EDR_AGENT_ETW_SENSORS=0 (or force-on via EDR_AGENT_ETW=1); a no-op
// when opted out or if the session cannot be started (injection telemetry is
// additive, no polling fallback).
func (c *ETWRemoteThreadCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	c.agentID = agentID
	c.sender = sender
	if !etwSensorsEnabled() || sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		slog.Warn("ETWリモートスレッド監視を開始できませんでした", "error", err)
		return nil
	}
	slog.Info("ETWリモートスレッド監視を開始しました (Microsoft-Windows-Kernel-Process, THREAD)")
	return nil
}

func (c *ETWRemoteThreadCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, remoteThreadSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWRemoteThreadCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(kernelProcessGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel-process provider: %w", err)
	}
	// THREAD keyword only — we want ThreadStart (id 3), not the process/image firehose.
	prov.MatchAnyKeyword = keywordThread
	prov.EnableLevel = 0xFF

	session := etw.NewRealTimeSession(remoteThreadSessionName)
	if err := session.EnableProvider(prov); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("enable provider: %w", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(session)
	consumer.EventCallback = func(e *etw.Event) error {
		c.handleETWEvent(e)
		return nil
	}
	if err := consumer.Start(); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("start consumer: %w", err)
	}

	c.etwSession = session
	c.etwConsumer = consumer
	return consumer, nil
}

func (c *ETWRemoteThreadCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent turns a Kernel-Process ThreadStart into a create_remote_thread
// finding when it looks like injection (creator ≠ target, creator user-writable).
func (c *ETWRemoteThreadCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWリモートスレッド処理でパニックを回復しました", "panic", r)
		}
	}()

	if e.System.EventID != etwThreadStartID {
		return
	}

	// Header PID = the process that created the thread (the injector).
	sourcePID := e.System.Execution.ProcessID
	// Payload ProcessID = the process the new thread will run in (the target).
	var targetPID uint32
	if s, ok := e.GetPropertyString("ProcessID"); ok {
		if v, err := strconv.ParseUint(s, 0, 32); err == nil {
			targetPID = uint32(v)
		}
	}
	// Not a cross-process (remote) thread, or unusable PIDs → ignore. PIDs 0/4 are
	// the kernel/System; process-start initial threads originate there too.
	if targetPID == 0 || sourcePID == 0 || sourcePID == 4 || sourcePID == targetPID {
		return
	}

	sourceImage := pidToName(sourcePID)
	// Noise gate: normal thread-creators (csrss.exe, services.exe, the process
	// itself) live under %SystemRoot%; injectors run from user-writable paths.
	// Skipping SystemRoot creators removes the process-start firehose and matches
	// the SigmaHQ rule's SourceImage|startswith C:\Users\/Temp/ProgramData intent.
	if sourceImage == "" || isSystemRootPath(sourceImage) {
		return
	}
	targetImage := pidToName(targetPID)

	batch := collector.BuildRemoteThreadEvent(c.agentID, collector.RemoteThreadPayload(
		int(sourcePID), sourceImage, int(targetPID), targetImage))
	if batch == nil {
		return
	}
	if err := c.sender.SendEvents(context.Background(), batch); err != nil {
		slog.Debug("[remote_thread] イベント送信失敗", "error", err)
	}
}

func (c *ETWRemoteThreadCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// isSystemRootPath reports whether an image path lives under the Windows
// directory (case-insensitive), i.e. a normal system component.
func isSystemRootPath(p string) bool {
	return strings.Contains(strings.ToLower(p), `\windows\`)
}
