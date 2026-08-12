package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// hostIntegrityPayload is the JSON carried by a host_integrity event — a
// syscall-level signal that bypasses the CommandLine-only rules for the same
// techniques (a custom or renamed binary calling the syscall directly evades
// a rule that matches on `insmod`/`nsenter`/`chmod +s` text). action
// classifies which technique fired:
//
//	kernel_module_load    T1547.006 (init_module/finit_module)
//	namespace_manipulation T1611     (unshare/setns)
//	capability_set         T1548.001 (capset)
//
// process_name/command_line/pid reuse the same field names process_creation
// events already populate, so existing curate field-support and the Sigma
// alias layer need no changes for rules built on this event.
type hostIntegrityPayload struct {
	Action      string `json:"action"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line"`
}

// HostIntegrityPayload constructs the payload for a host_integrity event.
// commandLine may be empty (the calling process exited before /proc could be
// read, or is a kernel thread) — the action/process_name signal still stands
// on its own.
func HostIntegrityPayload(action string, pid int, processName, commandLine string) hostIntegrityPayload {
	return hostIntegrityPayload{
		Action:      action,
		PID:         pid,
		ProcessName: processName,
		CommandLine: commandLine,
	}
}

// BuildHostIntegrityEvent encodes a host-integrity syscall signal into an
// EventBatch using the same "host_integrity:<uuid>:<json>" ID wire format as
// credential_access / memory findings (EVENT_TYPE_LOG), so it flows through
// the existing ingestion prefix-promotion with no proto change. Returns nil if
// the payload cannot be serialised.
func BuildHostIntegrityEvent(agentID string, payload hostIntegrityPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[host_integrity] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("host_integrity:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
