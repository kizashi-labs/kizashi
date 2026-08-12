package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// eventLogClearPayload is the JSON carried by an eventlog_cleared event: a
// Windows audit log was cleared. Clearing the Security or System event log is a
// high-signal defense-evasion move — attackers wipe it to destroy the very
// telemetry the rest of the pipeline relies on (Windows logs this as Security
// EventID 1102 "audit log was cleared" and System EventID 104 "log file was
// cleared"). The server surfaces it as T1070.001 (Indicator Removal: Clear
// Windows Event Logs). Channel + clearing user are the load-bearing fields.
type eventLogClearPayload struct {
	Channel    string `json:"channel"`     // "Security" | "System"
	User       string `json:"user"`        // account that cleared the log (best-effort)
	BackupPath string `json:"backup_path"` // System/104 only: pre-clear backup, if any
}

// EventLogClearPayload constructs the payload for an eventlog_cleared event.
func EventLogClearPayload(channel, user, backupPath string) eventLogClearPayload {
	return eventLogClearPayload{Channel: channel, User: user, BackupPath: backupPath}
}

// BuildEventLogClearEvent encodes an audit-log-cleared finding into an EventBatch
// using the same "<type>:<uuid>:<json>" ID wire format as pipe_created /
// create_remote_thread (EVENT_TYPE_LOG), so it flows through the existing
// ingestion prefix-promotion with no proto change. Returns nil on serialise error.
func BuildEventLogClearEvent(agentID string, payload eventLogClearPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[eventlog_cleared] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("eventlog_cleared:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
