package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WMI event-subscription operations, as they appear in the emitted payload's
// `event_type` field. These names match Sysmon's WmiEvent trio (EventID 19/20/21)
// because that is what SigmaHQ's `wmi_event` logsource category selects on —
// sigma_category.go maps our internal `wmi_activity` type onto that category, so
// emitting Sysmon's vocabulary is what makes those rules reachable at all.
//
// The data itself comes from Microsoft-Windows-WMI-Activity/Operational, not from
// Sysmon. Sysmon splits one subscription into three events; the ETW provider
// reports the registration as a single 5861 record carrying the query, the
// consumer and the namespace together. We therefore emit WmiBindingEvent for a
// 5861 and let the filter/consumer fields carry the detail, rather than inventing
// three synthetic events from one observation.
const (
	WMIEventTypeFilter   = "WmiFilterEvent"
	WMIEventTypeConsumer = "WmiConsumerEvent"
	WMIEventTypeBinding  = "WmiBindingEvent"
	// WMIEventTypeOperation has no Sysmon equivalent. It carries 5858 (a WMI
	// operation, including remote ones), which is the lateral-movement signal
	// Sysmon's WmiEvent trio does not cover.
	WMIEventTypeOperation = "WmiOperation"
)

// wmiActivityPayload is the JSON carried by a wmi_activity event.
//
// Field names are deliberately the SigmaHQ `wmi_event` ones (EventType, Operation,
// User, Query, Consumer, Destination, Name) rather than the raw ETW property
// names. The server flattens this payload and the Sigma evaluator matches on the
// flattened keys, so using the ETW spelling would make every community rule for
// this category silently non-matching — the exact "sensor lands but rules never
// fire" shape this codebase has hit repeatedly (see P5-5 / P5-10).
type wmiActivityPayload struct {
	EventType string `json:"event_type"` // WmiFilterEvent / WmiConsumerEvent / WmiBindingEvent / WmiOperation
	Operation string `json:"operation"`  // the WMI operation text (5858/5861)
	User      string `json:"user"`       // SID or account that owns the subscription / made the call
	Query     string `json:"query"`      // WQL of the event filter (5861)
	Consumer  string `json:"consumer"`   // consumer definition, e.g. CommandLineEventConsumer="..."
	Name      string `json:"name"`       // filter/consumer name where the provider supplies one
	Namespace string `json:"namespace"`  // e.g. //./root/subscription
	// Destination is the remote endpoint for a remote WMI call (5858's
	// ClientMachine). Empty for local activity.
	Destination string `json:"destination"`
	// PossibleCause is the provider's own hint on 5858 failures. Kept because it
	// often names the offending consumer when Consumer itself is blank.
	PossibleCause string `json:"possible_cause,omitempty"`
	EventID       int    `json:"event_id"` // originating ETW event ID (5858 / 5861)
	PID           int    `json:"pid"`
}

// WMIActivityPayload constructs the payload for a wmi_activity event.
func WMIActivityPayload(eventType, operation, user, query, consumer, name, namespace, destination, possibleCause string, eventID, pid int) wmiActivityPayload {
	return wmiActivityPayload{
		EventType:     eventType,
		Operation:     operation,
		User:          user,
		Query:         query,
		Consumer:      consumer,
		Name:          name,
		Namespace:     namespace,
		Destination:   destination,
		PossibleCause: possibleCause,
		EventID:       eventID,
		PID:           pid,
	}
}

// BuildWMIActivityEvent encodes a WMI-Activity finding into an EventBatch using
// the same "<type>:<uuid>:<json>" ID wire format as ps_module /
// create_remote_thread / credential_access findings (EVENT_TYPE_LOG), so it flows
// through the existing ingestion prefix-promotion with no proto change.
// Returns nil if the payload cannot be serialised.
func BuildWMIActivityEvent(agentID string, payload wmiActivityPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[wmi_activity] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("wmi_activity:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
