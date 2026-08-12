package detection

import "testing"

// The WMI-Activity sensor emits SigmaHQ's `wmi_event` field names rather than the
// raw ETW property spellings, and the whole point of that choice is that rules in
// that category match the flattened event without further translation. This test
// fixes that end of the contract: the payload shape the collector produces, run
// through the same flatten path the live handler uses.
//
// It matters because the failure mode here is silent. A sensor that emits with
// the wrong field names produces events that are stored, counted, and never
// matched — the shape recorded as P5-5 and P5-10 in the debt log, and the reason
// the AlertPipeline subscription bug went unnoticed for months.
//
// ⚠️ This proves the SERVER end only. Whether Microsoft-Windows-WMI-Activity
// actually delivers these properties on a live host is unverified — see the note
// on ETWWMIActivityCollector.
func TestWMIActivityEventMatchesWmiEventCategoryRule(t *testing.T) {
	// Load the SHIPPED built-in set, not an inline copy of the rule. An inline
	// copy would keep passing if the built-in were dropped, renamed, or edited
	// into something that no longer matches — which is the failure this test is
	// for. server-api's AlertPipeline evaluates exactly this set.
	ev := NewSigmaEvaluator()
	if n := LoadBuiltinRules(ev); n == 0 {
		t.Fatal("no built-in rules loaded")
	}

	// The envelope ingestion publishes for a promoted wmi_activity event: the
	// collector's JSON becomes the nested data payload.
	envelopeFor := func(data map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"agent_id": "11111111-1111-1111-1111-111111111111",
			"hostname": "WIN-BOX",
			"platform": "windows",
			"type":     "wmi_activity",
			"data":     data,
		}
	}
	fires := func(t *testing.T, data map[string]interface{}) bool {
		t.Helper()
		flat := flattenNormalizedEvent(envelopeFor(data))
		return len(ev.EvaluateEvent(flat)) > 0
	}

	t.Run("executing consumer fires", func(t *testing.T) {
		if !fires(t, map[string]interface{}{
			"event_type": "WmiBindingEvent",
			"query":      "SELECT * FROM __InstanceModificationEvent WITHIN 60",
			"consumer":   `CommandLineEventConsumer="Updater"`,
			"namespace":  "//./root/subscription",
			"user":       "S-1-5-18",
			"event_id":   float64(5861),
		}) {
			t.Error("a CommandLineEventConsumer binding must fire T1546.003")
		}
	})

	t.Run("script consumer fires", func(t *testing.T) {
		if !fires(t, map[string]interface{}{
			"event_type": "WmiBindingEvent",
			"consumer":   `ActiveScriptEventConsumer="Logger"`,
			"event_id":   float64(5861),
		}) {
			t.Error("an ActiveScriptEventConsumer binding must fire T1546.003")
		}
	})

	// A subscription alone is not the technique. Management tooling registers
	// these routinely, and firing on every binding would reproduce exactly the
	// non-discriminating-selector problem measured in the 2026-08-03 FP soak.
	t.Run("non-executing consumer stays silent", func(t *testing.T) {
		if fires(t, map[string]interface{}{
			"event_type": "WmiBindingEvent",
			"consumer":   `NTEventLogEventConsumer="AuditForwarder"`,
			"event_id":   float64(5861),
		}) {
			t.Error("a log-forwarding consumer is not T1546.003 and must not fire")
		}
	})

	// 5858 operations share the event type but carry no consumer; they exist for
	// remote-WMI detection, not persistence.
	t.Run("operation record stays silent", func(t *testing.T) {
		if fires(t, map[string]interface{}{
			"event_type":  "WmiOperation",
			"operation":   "Start IWbemServices::ExecMethod",
			"destination": "DC01",
			"event_id":    float64(5858),
		}) {
			t.Error("a WmiOperation record must not fire the persistence rule")
		}
	})
}

// The fields the collector emits must all be recognised as supported, or rules
// selecting on them are deferred as "unsupported" and never evaluated — a false
// green that looks identical to "no WMI activity happened".
func TestWMIActivityFieldsAreSupported(t *testing.T) {
	supported := SupportedSigmaFields()
	for _, f := range []string{
		"event_type", "operation", "user", "query",
		"consumer", "name", "namespace", "destination", "event_id",
	} {
		if !supported[f] {
			t.Errorf("wmi_activity emits %q but it is not field-supported — rules selecting on it would be deferred, not evaluated", f)
		}
	}
}
