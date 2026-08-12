//go:build windows

package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

const (
	// powerShellGUID is the Microsoft-Windows-PowerShell ETW provider. With
	// ScriptBlock logging it emits event 4104 carrying the DEOBFUSCATED script
	// text — visibility a command line (e.g. "-enc <base64>") never gives.
	powerShellGUID    = "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}"
	scriptSessionName = "EDR-Agent-Script"
	etwScriptBlockID  = 4104
	// amsiGUID is the Microsoft-Antimalware-Scan-Interface ETW provider. It
	// delivers the buffer AMSI scanned — covering PowerShell, VBScript, JScript,
	// .NET, WMI and Office macros (broader than PowerShell ScriptBlock alone).
	amsiGUID = "{2a576b87-09a7-520e-c21a-4942f0271d67}"
)

// ETWScriptCollector captures PowerShell ScriptBlock content via ETW for
// fileless/obfuscated-script detection.
type ETWScriptCollector struct {
	cancel      context.CancelFunc
	out         chan<- collector.ScriptContentEvent
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWScriptCollector() *ETWScriptCollector {
	return &ETWScriptCollector{}
}

// Start begins ETW PowerShell ScriptBlock monitoring. Additive sensor: default
// ON, opt-out via EDR_AGENT_ETW_SENSORS=0 (or force-on via EDR_AGENT_ETW=1);
// no-op when opted out or on failure (script telemetry is additive — there is no
// polling equivalent).
func (c *ETWScriptCollector) Start(ctx context.Context, out chan<- collector.ScriptContentEvent) error {
	c.out = out
	if !etwSensorsEnabled() {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		slog.Warn("ETWスクリプト監視を開始できませんでした", "error", err)
		return nil
	}
	slog.Info("ETWスクリプト監視を開始しました (Microsoft-Windows-PowerShell ScriptBlock + AMSI)")
	return nil
}

func (c *ETWScriptCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, scriptSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWScriptCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(powerShellGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve powershell provider: %w", err)
	}
	prov.EnableLevel = 0xFF // verbose — deliver ScriptBlock (4104) events

	session := etw.NewRealTimeSession(scriptSessionName)
	if err := session.EnableProvider(prov); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("enable provider: %w", err)
	}

	// Also enable the AMSI provider (best-effort — older hosts may lack it).
	if amsiProv, perr := etw.ParseProvider(amsiGUID); perr == nil {
		amsiProv.EnableLevel = 0xFF
		if err := session.EnableProvider(amsiProv); err != nil {
			slog.Warn("AMSI ETWプロバイダを有効化できませんでした(継続)", "error", err)
		}
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

func (c *ETWScriptCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent converts a PowerShell ScriptBlock (4104) or an AMSI scan event
// into a ScriptContentEvent. Empty content is dropped.
func (c *ETWScriptCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWスクリプト処理でパニックを回復しました", "panic", r)
		}
	}()

	var engine, content string
	var blockNum, blockTotal uint32

	if text, ok := e.GetPropertyString("ScriptBlockText"); ok && text != "" {
		// PowerShell ScriptBlock logging (4104).
		if e.System.EventID != etwScriptBlockID {
			return
		}
		engine, content = "powershell", text
		if n, ok := e.GetPropertyString("MessageNumber"); ok {
			if v, err := strconv.ParseUint(n, 0, 32); err == nil {
				blockNum = uint32(v)
			}
		}
		if t, ok := e.GetPropertyString("MessageTotal"); ok {
			if v, err := strconv.ParseUint(t, 0, 32); err == nil {
				blockTotal = uint32(v)
			}
		}
	} else if buf, ok := e.GetPropertyString("Content"); ok && buf != "" {
		// AMSI scan buffer. The provider/app (PowerShell, VBScript, .NET, …) is in
		// AppName; the scanned content may be hex-encoded.
		engine = "amsi"
		if app, ok := e.GetPropertyString("AppName"); ok && app != "" {
			engine = "amsi:" + app
		}
		content = decodeMaybeHex(buf)
	} else {
		return
	}
	if content == "" {
		return
	}

	sum := sha256.Sum256([]byte(content))
	evt := collector.ScriptContentEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Engine:      engine,
		Content:     content,
		PID:         e.System.Execution.ProcessID,
		ContentHash: hex.EncodeToString(sum[:]),
		BlockNumber: blockNum,
		BlockTotal:  blockTotal,
	}

	select {
	case c.out <- evt:
	default:
	}
}

// decodeMaybeHex returns the decoded string if s is an even-length hex blob
// (as AMSI often renders the scanned buffer), otherwise s unchanged.
func decodeMaybeHex(s string) string {
	if len(s) < 2 || len(s)%2 != 0 {
		return s
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return s
		}
	}
	if b, err := hex.DecodeString(s); err == nil {
		// Trim trailing NULs that AMSI buffers sometimes carry.
		return strings.TrimRight(string(b), "\x00")
	}
	return s
}

func (c *ETWScriptCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
