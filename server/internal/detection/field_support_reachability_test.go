package detection

import "testing"

// emittedEventFields lists the flat field keys that ingestion's normalizeEventData
// (server/internal/ingestion/handler.go) produces for each event type. Command
// payload keys (isolate, kill_process, quarantine_file, …) are intentionally
// excluded — they are agent-command envelopes, not detection event fields.
//
// This mirrors the map literals in handler.go. Keep the two in sync: when a new
// field is added to an event in ingestion, add it here too.
var emittedEventFields = map[string][]string{
	"process":   {"process_name", "pid", "ppid", "command_line", "image_path", "username", "action", "integrity_level"},
	"network":   {"src_ip", "src_port", "dst_ip", "dst_port", "protocol", "direction", "bytes_sent", "bytes_recv", "state"},
	"dns":       {"query", "query_type", "answers"},
	"registry":  {"key_path", "value_name", "value_data", "operation", "process_name"},
	"auth":      {"username", "action", "success", "source_ip", "auth_method", "failure_reason", "logon_type"},
	"file":      {"path", "old_path", "operation", "process_name", "pid", "file_size"},
	"imageload": {"image_loaded", "signed", "signature_status", "signer"},
}

// TestEmittedEventFieldsAreSupported is a reachability guard: every field the
// agent/ingestion actually emits for an event MUST be in SupportedSigmaFields, so
// the field-support gate never falsely defers a Sigma/SigmaHQ rule (or marks a
// built-in inert) for keying on real, available telemetry. This is the systematic
// guard for the silent-inert class of bug: bytes_sent/state/old_path/file_size
// were emitted by ingestion yet absent from the supported set, so any rule using
// them was quietly suppressed. A failure here means: add the field to
// SupportedSigmaFields (if genuinely emitted) or remove it from the list above.
func TestEmittedEventFieldsAreSupported(t *testing.T) {
	supported := SupportedSigmaFields()
	for evtType, fields := range emittedEventFields {
		for _, f := range fields {
			if !supported[f] {
				t.Errorf("event %q emits flat field %q but SupportedSigmaFields() does not list it — "+
					"rules keying on it are falsely deferred/inert (cf. the bytes_sent/operation reachability bugs)",
					evtType, f)
			}
		}
	}
}
