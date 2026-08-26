//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
)

const (
	// psModuleSessionName is a dedicated ETW session for PowerShell Module Logging.
	// It subscribes to the same Microsoft-Windows-PowerShell provider (powerShellGUID,
	// defined in script_etw.go) as the ScriptBlock collector but keeps its own session
	// so the well-tested 4104 path is untouched; the handler filters to EventID 4103.
	psModuleSessionName = "EDR-Agent-PSModule"
	// etwModuleLoggingID is the PowerShell "Executing Pipeline" event (module logging).
	etwModuleLoggingID = 4103
)

// ETWPSModuleCollector captures PowerShell Module Logging (4103) via ETW. Where
// ScriptBlock (4104) carries the deobfuscated source, 4103 carries the invoked
// commands + bound parameters (Payload) and a context block (ContextInfo) — the
// fields SigmaHQ `ps_module` rules (Invoke-Obfuscation, malicious cmdlets, …)
// select on. Emitted as a create_remote_thread-style ps_module finding through
// the event sender (no proto change).
type ETWPSModuleCollector struct {
	cancel      context.CancelFunc
	agentID     string
	sender      collector.EventSender
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWPSModuleCollector() *ETWPSModuleCollector {
	return &ETWPSModuleCollector{}
}

// Start begins ETW PowerShell module-logging monitoring. Additive sensor:
// default ON, opt-out via EDR_AGENT_ETW_SENSORS=0 (or force-on via
// EDR_AGENT_ETW=1); a no-op when opted out or if the session cannot be started
// (module-logging telemetry is additive, no polling fallback).
func (c *ETWPSModuleCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	c.agentID = agentID
	c.sender = sender
	if !etwSensorsEnabled() || sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorETWPSModule, err)
		return nil
	}
	slog.Info("ETW PowerShellモジュールログ監視を開始しました (Microsoft-Windows-PowerShell, 4103)")
	return nil
}

func (c *ETWPSModuleCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, psModuleSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWPSModuleCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(powerShellGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve powershell provider: %w", err)
	}
	prov.EnableLevel = 0xFF // verbose — deliver module-logging (4103) events

	session := etw.NewRealTimeSession(psModuleSessionName)
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

func (c *ETWPSModuleCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent turns a PowerShell module-logging (4103) event into a ps_module
// finding. Events without a Payload and ContextInfo are dropped.
func (c *ETWPSModuleCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETW PowerShellモジュールログ処理でパニックを回復しました", "panic", r)
		}
	}()

	if e.System.EventID != etwModuleLoggingID {
		return
	}

	payload, _ := e.GetPropertyString("Payload")
	contextInfo, _ := e.GetPropertyString("ContextInfo")
	if payload == "" && contextInfo == "" {
		return
	}

	pid := int(e.System.Execution.ProcessID)
	if s, ok := e.GetPropertyString("ProcessId"); ok {
		if v, err := strconv.ParseUint(s, 0, 32); err == nil && v != 0 {
			pid = int(v)
		}
	}

	batch := collector.BuildPSModuleEvent(c.agentID, collector.PSModulePayload(payload, contextInfo, pid))
	if batch == nil {
		return
	}
	if err := c.sender.SendEvents(context.Background(), batch); err != nil {
		slog.Debug("[ps_module] イベント送信失敗", "error", err)
	}
}

func (c *ETWPSModuleCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
