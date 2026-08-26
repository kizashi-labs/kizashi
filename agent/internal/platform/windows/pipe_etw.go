//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
)

const (
	// pipeSessionName is a dedicated ETW session for named-pipe creation.
	pipeSessionName = "EDR-Agent-NamedPipe"
	// kernelFileGUID is the Microsoft-Windows-Kernel-File provider. Named pipes are
	// file objects under \Device\NamedPipe\, so their creation surfaces as Kernel-File
	// Create events. (Sysmon uses a minifilter for EID 17/18; the Kernel-File ETW route
	// is the driver-free mirror of our other ETW sensors — see the volume note below.)
	kernelFileGUID = "{edd08927-9cc4-4e65-b970-c2560fb5c289}"
	// keywordFileCreate = KERNEL_FILE_KEYWORD_CREATE, keywordFileCreateNew =
	// KERNEL_FILE_KEYWORD_CREATE_NEW_FILE. Both are enabled so pipe creation is caught
	// whether the OS reports it as a Create (open of the pipe device) or a new-file
	// create; the \Device\NamedPipe\ path filter drops all non-pipe file activity.
	keywordFileCreate    uint64 = 0x80
	keywordFileCreateNew uint64 = 0x1000
	// namedPipeDevicePrefix is the NT device path all named pipes live under. The
	// Sysmon-style PipeName is the remainder (e.g. \Device\NamedPipe\msagent_5x → the
	// rule matches \msagent_5x), so we strip the device dir and keep the leading "\".
	namedPipeDevicePrefix = `\device\namedpipe`
)

// ETWPipeCollector captures named-pipe creation via ETW for C2 named-pipe
// detection (Cobalt Strike & clones). It subscribes to Microsoft-Windows-Kernel-
// File with the Create keywords and forwards only paths under \Device\NamedPipe\,
// emitted as a pipe_created finding through the event sender (no proto change).
//
// NOTE (volume): the Create keyword delivers ALL file creates on the host, filtered
// down to pipes in the callback. This is opt-in (EDR_AGENT_ETW, shared with the
// other ETW sensors) and additive; a production-grade lower-overhead source is a
// named-pipe minifilter (as Sysmon uses). The exact create EventID / property names
// are validated on a real box (方針A: code-first, real-box firing is follow-up).
type ETWPipeCollector struct {
	cancel      context.CancelFunc
	agentID     string
	sender      collector.EventSender
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWPipeCollector() *ETWPipeCollector {
	return &ETWPipeCollector{}
}

// Start begins ETW named-pipe monitoring. Additive sensor: default ON, opt-out
// via EDR_AGENT_ETW_SENSORS=0 (or force-on via EDR_AGENT_ETW=1); a no-op when
// opted out or if the session cannot be started (pipe telemetry is additive, no
// polling fallback).
func (c *ETWPipeCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	c.agentID = agentID
	c.sender = sender
	if !etwSensorsEnabled() || sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorETWPipe, err)
		return nil
	}
	slog.Info("ETW名前付きパイプ監視を開始しました (Microsoft-Windows-Kernel-File, Create)")
	return nil
}

func (c *ETWPipeCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, pipeSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWPipeCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(kernelFileGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel-file provider: %w", err)
	}
	// Restrict to the create keywords so we receive file-create events (not the
	// read/write/setinfo firehose); the callback then keeps only \Device\NamedPipe\.
	prov.MatchAnyKeyword = keywordFileCreate | keywordFileCreateNew
	prov.EnableLevel = 0xFF

	session := etw.NewRealTimeSession(pipeSessionName)
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

func (c *ETWPipeCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent turns a Kernel-File create whose target is a named pipe into a
// pipe_created finding. Non-pipe file creates are dropped in-callback (cheap prefix
// check), keeping the per-event cost minimal despite the create firehose.
func (c *ETWPipeCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETW名前付きパイプ処理でパニックを回復しました", "panic", r)
		}
	}()

	name, ok := e.GetPropertyString("FileName")
	if !ok || name == "" {
		return
	}
	pipeName := namedPipeFromPath(name)
	if pipeName == "" {
		return // not a named pipe
	}

	pid := int(e.System.Execution.ProcessID)
	image := ""
	if pid > 0 {
		image = pidToName(uint32(pid))
	}

	batch := collector.BuildNamedPipeEvent(c.agentID, collector.NamedPipePayload(pipeName, image, pid))
	if batch == nil {
		return
	}
	if err := c.sender.SendEvents(context.Background(), batch); err != nil {
		slog.Debug("[pipe_created] イベント送信失敗", "error", err)
	}
}

// namedPipeFromPath returns the Sysmon-style pipe name (leading "\" + name) when p
// is a named-pipe device path, else "". e.g. \Device\NamedPipe\msagent_5x → \msagent_5x
// (matching the SigmaHQ `PipeName|contains: '\msagent_'` selection). The check is
// case-insensitive; the returned name preserves the original casing after the prefix.
func namedPipeFromPath(p string) string {
	if !strings.HasPrefix(strings.ToLower(p), namedPipeDevicePrefix) {
		return ""
	}
	name := p[len(namedPipeDevicePrefix):]
	if name == "" {
		return `\` // the pipe root itself
	}
	if name[0] != '\\' {
		// e.g. "\Device\NamedPipeFoo" — not actually under the pipe dir.
		return ""
	}
	return name
}

func (c *ETWPipeCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
