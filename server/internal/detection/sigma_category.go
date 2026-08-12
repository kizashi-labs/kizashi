// Package detection — sigma_category.go: maps this platform's ingestion event
// types (the "type" field on a flattened event, set by
// server/internal/ingestion/handler.go's promoteEventType) to the Sigma
// logsource.category vocabulary used by sigma_builtins.go and SigmaHQ-synced
// rules. Used only for the SHADOW-MODE mismatch check in sigma_evaluator.go
// (P4-9, docs/技術的負債と改善計画.md) -- it never filters a match, only flags
// one that looks miscategorized so the mapping can be validated against the
// live rule corpus before anything is ever enforced.
package detection

// eventTypeCategories maps an event "type" value to the set of Sigma
// logsource.category values a rule may declare and still legitimately match
// that event. Built from the exhaustive lists on both sides:
//   - event types: server/internal/ingestion/handler.go promoteEventType /
//     eventTypeString (the v1.EventType enum plus the "<type>:" id-prefix
//     log-style findings)
//   - categories: every distinct `category:` value across the 174 builtin
//     rules (sigma_builtins.go), 2026-07-20
//
// Deliberately permissive where one event type can plausibly satisfy more
// than one category (e.g. "file" covers both file_event/write and
// file_access/read -- the proto does not split these into separate types)
// rather than risk a false mismatch in shadow mode.
//
// This map has a SECOND consumer: alert_pipeline.go derives the pipeline's NATS
// subscription from its keys, so a type absent here is not merely unchecked in
// shadow mode -- it is never evaluated at all. Adding an event type therefore
// means "the pipeline should see this", and the value means "and these are the
// categories a rule may legitimately declare for it".
//
// An empty value list is meaningful: the type IS evaluated, but no Sigma
// category corresponds to it, so any rule that declares a category and still
// matches is a genuine mismatch. Uncategorized rules (the majority) match
// normally, since categoryCompatible short-circuits on an empty rule category.
//
// process_stats / process_block / resource_usage stay absent: they are
// high-rate pure telemetry or already-decided findings handled by the
// typedFindings() path (engine.go), and feeding them to the pipeline would cost
// throughput for no detection.
var eventTypeCategories = map[string][]string{
	"process":              {"process_creation"},
	"file":                 {"file_event", "file_access"},
	"network":              {"network_connection"},
	"dns":                  {"dns_query"},
	"registry":             {"registry_event"},
	"auth":                 {"authentication"},
	"image_load":           {"image_load"},
	"script":               {"ps_script"},
	"credential_access":    {"process_access"},
	"create_remote_thread": {"create_remote_thread"},
	// Both spellings intentionally. Ingestion promotes the `pipe_created:` id
	// prefix to the type "pipe_created"; "named_pipe" is the name the rule corpus
	// and the kill-chain migrations use. Mapping only one of them made the other
	// look like it had no entry at all — which categoryCompatible treats as
	// INCOMPATIBLE-with-everything, i.e. a shadow-mode mismatch warning on every
	// legitimate pipe event.
	"pipe_created": {"pipe_created"},
	"named_pipe":   {"pipe_created"},
	"wmi_activity": {"wmi_event"},
	"ps_classic":   {"ps_script"},
	"device_event": {"device_event"},
	// PowerShell module logging (EventID 4103). SigmaHQ has a dedicated
	// ps_module category; the agent's collector/ps_module.go emits it and
	// ingestion promotes the "ps_module:" id prefix.
	"ps_module": {"ps_module"},
	// Agent self-protection findings (the agent was killed, its binary or config
	// was modified, its watchdog vanished, something tried to terminate it).
	//
	// There is no SigmaHQ category for these — they are this product's own
	// telemetry about itself — so the category is simply "tamper", matching what
	// migration 378 and the builtins declare.
	//
	// Deliberately NOT routed through typedFindings() the way process_block and
	// device_event are, even though these are likewise already-decided findings.
	// typedFindings runs in engine.go, i.e. server-detect, which is the consumer
	// that chronically lags (P4-6). "Someone is switching the sensor off" is the
	// last signal that should land only on the slow path, so it goes through the
	// rule layer, where server-api's caught-up AlertPipeline evaluates the
	// builtins. Subscribing here is what makes that happen — alert_pipeline.go
	// derives its subject filter from this map.
	"tamper": {"tamper"},
	// In-memory scan findings. No Sigma category corresponds to them — the typed
	// memory findings come from typedFindings() — but the pipeline still runs IOC
	// matching and UEBA over the event, which is why it is subscribed rather than
	// omitted. Empty list = evaluated, but a rule declaring any category and
	// matching a memory event is a genuine mismatch.
	"memory": {},
}

// categoryCompatible reports whether ruleCategory is a plausible match for an
// event of the given type. An empty ruleCategory (a rule with no
// logsource.category, or one this repo's YAML parser did not populate) is
// always treated as compatible -- there is nothing to check. An event type
// with no entry in eventTypeCategories is treated as INCOMPATIBLE with any
// declared category, since no builtin rule's category is meant to receive it
// (see eventTypeCategories doc comment).
func categoryCompatible(eventType, ruleCategory string) bool {
	if ruleCategory == "" {
		return true
	}
	cats, ok := eventTypeCategories[eventType]
	if !ok {
		return false
	}
	for _, c := range cats {
		if c == ruleCategory {
			return true
		}
	}
	return false
}
