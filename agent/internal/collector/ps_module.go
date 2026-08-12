package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// psModulePayload is the JSON carried by a ps_module event: the details of a
// PowerShell pipeline execution captured from Module Logging (Microsoft-Windows-
// PowerShell EventID 4103). Unlike ScriptBlock logging (4104, the `script` type),
// which carries the deobfuscated source, 4103 carries the *invoked commands and
// their bound parameters* — the `Payload` field — plus a `ContextInfo` block
// (host, user, command name, engine version, …). SigmaHQ `ps_module` category
// rules (Invoke-Obfuscation launchers, malicious cmdlets, in-memory compile, …)
// select on exactly these two field names, which the `script` path cannot supply.
//
// NOTE: 4103 is only as rich as the host's PowerShell Module Logging config
// (EnableModuleLogging + ModuleNames=*). ScriptBlock (4104) is emitted to the
// verbose ETW provider regardless, but module-logging detail depends on policy —
// the collector forwards whatever the provider delivers.
type psModulePayload struct {
	Payload     string `json:"payload"`      // invoked commands + parameter bindings
	ContextInfo string `json:"context_info"` // host/user/command-name context block
	PID         int    `json:"pid"`
}

// PSModulePayload constructs the payload for a ps_module event.
func PSModulePayload(payload, contextInfo string, pid int) psModulePayload {
	return psModulePayload{
		Payload:     payload,
		ContextInfo: contextInfo,
		PID:         pid,
	}
}

// BuildPSModuleEvent encodes a PowerShell module-logging (4103) finding into an
// EventBatch using the same "<type>:<uuid>:<json>" ID wire format as
// create_remote_thread / credential_access / memory findings (EVENT_TYPE_LOG),
// so it flows through the existing ingestion prefix-promotion with no proto
// change. Returns nil if the payload cannot be serialised.
func BuildPSModuleEvent(agentID string, payload psModulePayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[ps_module] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("ps_module:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
