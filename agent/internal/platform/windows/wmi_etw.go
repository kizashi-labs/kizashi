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
	// wmiActivitySessionName is a dedicated ETW session for WMI activity.
	wmiActivitySessionName = "EDR-Agent-WMIActivity"
	// wmiActivityGUID is Microsoft-Windows-WMI-Activity.
	wmiActivityGUID = "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}"

	// etwWMIOperationID (5858) is a WMI operation record. It carries the calling
	// user and, for remote calls, the client machine — the lateral-movement
	// signal (T1047) that Sysmon's WmiEvent trio does not cover.
	etwWMIOperationID = 5858
	// etwWMISubscriptionID (5861) is an event-subscription registration: the WQL
	// filter, the consumer and the namespace in one record. This is the T1546.003
	// persistence signal and the reason this sensor exists.
	etwWMISubscriptionID = 5861
)

// ETWWMIActivityCollector captures WMI persistence and remote-operation activity
// from Microsoft-Windows-WMI-Activity.
//
// Scope is deliberately two event IDs. 5857 (provider load) fires on ordinary WMI
// use — every management script, every inventory agent — and adding it would put
// a high-rate, low-discrimination stream into the detection path. This codebase
// has measured what that costs: the 2026-08-03 FP soak showed non-discriminating
// selectors dominating the false-positive list, and the lesson recorded there is
// to encode "was the technique used", not "was the subsystem touched". 5861 is a
// technique (persistence via event subscription); 5858 with a ClientMachine is a
// technique (remote WMI execution); 5857 is neither.
//
// LIVE-VERIFIED on 2026-08-04 against a real provider (the windows-latest CI
// runner; see wmi_etw_live_windows_test.go, which registers an actual event
// subscription and asserts this collector emits). Observed for a 5861:
//
//	event_type = WmiBindingEvent
//	event_id   = 5861
//	consumer   = CommandLineEventConsumer="<name>"
//	namespace  = //./root/subscription
//
// Two properties did NOT come back as the manifest reading suggested, and the
// difference matters to anyone writing rules against this event:
//
//   - Query carried the FILTER NAME, not the WQL text. A rule that expects to
//     find "SELECT * FROM __InstanceModificationEvent" in `query` will never
//     match. The detection rule keys on the consumer type precisely because that
//     is the part that identifies the technique; `query` is context, not a
//     selector.
//   - User came back empty (none of User / CreatorSID / UserName was populated).
//     Do not build a rule that requires it.
//
// The etwProp fallbacks did their job — nothing came back blank that the sensor
// needs — but the check stays in CI because a future Windows build can rename
// these again, and the failure mode is silent: wrong spelling produces an event
// with empty fields rather than an error.
type ETWWMIActivityCollector struct {
	cancel      context.CancelFunc
	agentID     string
	sender      collector.EventSender
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWWMIActivityCollector() *ETWWMIActivityCollector {
	return &ETWWMIActivityCollector{}
}

// Start begins ETW WMI-activity monitoring. Additive sensor: default ON, opt-out
// via EDR_AGENT_ETW_SENSORS=0 (or force-on via EDR_AGENT_ETW=1); a no-op when
// opted out or if the session cannot be started (no polling fallback exists for
// WMI subscriptions).
func (c *ETWWMIActivityCollector) Start(ctx context.Context, agentID string, sender collector.EventSender) error {
	c.agentID = agentID
	c.sender = sender
	if !etwSensorsEnabled() || sender == nil {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorETWWMI, err)
		return nil
	}
	slog.Info("ETW WMI監視を開始しました (Microsoft-Windows-WMI-Activity, 5858/5861)")
	return nil
}

func (c *ETWWMIActivityCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, wmiActivitySessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWWMIActivityCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(wmiActivityGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve wmi-activity provider: %w", err)
	}
	prov.EnableLevel = 0xFF

	session := etw.NewRealTimeSession(wmiActivitySessionName)
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

func (c *ETWWMIActivityCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// etwProp returns the first non-empty property among the given names.
//
// The manifest spelling has varied across Windows builds (Operation vs
// OperationId, ClientMachine vs ClientMachineFQDN, ESS vs Query), and a wrong
// guess here would not fail loudly — it would emit an event with empty fields
// that no rule matches, which is precisely the silent-inert shape this codebase
// keeps rediscovering. Trying the known spellings costs nothing.
func etwProp(e *etw.Event, names ...string) string {
	for _, n := range names {
		if v, ok := e.GetPropertyString(n); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return ""
}

func (c *ETWWMIActivityCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETW WMI処理でパニックを回復しました", "panic", r)
		}
	}()

	id := int(e.System.EventID)
	if id != etwWMIOperationID && id != etwWMISubscriptionID {
		return
	}

	pid := int(e.System.Execution.ProcessID)
	if s := etwProp(e, "ProcessID", "ProcessId"); s != "" {
		if v, err := strconv.ParseUint(s, 0, 32); err == nil && v != 0 {
			pid = int(v)
		}
	}

	user := etwProp(e, "User", "CreatorSID", "UserName")
	namespace := etwProp(e, "Namespace", "NamespaceName")

	var payload = collector.WMIActivityPayload("", "", user, "", "", "", namespace, "", "", id, pid)

	switch id {
	case etwWMISubscriptionID:
		query := etwProp(e, "Query", "ESS", "QueryString")
		consumer := etwProp(e, "Consumer", "CONSUMER", "ConsumerName")
		name := etwProp(e, "Name", "FilterName")
		cause := etwProp(e, "PossibleCause")
		// A subscription record with neither a query nor a consumer carries no
		// technique detail; forwarding it would only add volume.
		if query == "" && consumer == "" {
			return
		}
		payload = collector.WMIActivityPayload(
			collector.WMIEventTypeBinding,
			etwProp(e, "Operation"),
			user, query, consumer, name, namespace, "", cause, id, pid)

	case etwWMIOperationID:
		operation := etwProp(e, "Operation", "OperationId")
		client := etwProp(e, "ClientMachine", "ClientMachineFQDN")
		if operation == "" {
			return
		}
		payload = collector.WMIActivityPayload(
			collector.WMIEventTypeOperation,
			operation, user, "", "", "", namespace, client, etwProp(e, "PossibleCause"), id, pid)
	}

	batch := collector.BuildWMIActivityEvent(c.agentID, payload)
	if batch == nil {
		return
	}
	if err := c.sender.SendEvents(context.Background(), batch); err != nil {
		slog.Debug("[wmi_activity] イベント送信失敗", "error", err)
	}
}

func (c *ETWWMIActivityCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
