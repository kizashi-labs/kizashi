package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// remoteThreadPayload is the JSON carried by a create_remote_thread event: one
// process created a thread inside a DIFFERENT process. On Windows this is the
// Kernel-Process ETW ThreadStart where the event-header PID (the creator) differs
// from the payload PID (the thread's owning process) — the CreateRemoteThread /
// process-hollowing injection primitive (T1055.012 / Sysmon EID8). The server's
// detection engine matches SourceImage/TargetImage SigmaHQ rules against it.
type remoteThreadPayload struct {
	SourcePID   int    `json:"source_pid"`   // creator process (called CreateRemoteThread)
	SourceImage string `json:"source_image"` // creator image path
	TargetPID   int    `json:"target_pid"`   // process the new thread runs in
	TargetImage string `json:"target_image"` // target image path
}

// RemoteThreadPayload constructs the payload for a create_remote_thread event.
func RemoteThreadPayload(sourcePID int, sourceImage string, targetPID int, targetImage string) remoteThreadPayload {
	return remoteThreadPayload{
		SourcePID:   sourcePID,
		SourceImage: sourceImage,
		TargetPID:   targetPID,
		TargetImage: targetImage,
	}
}

// BuildRemoteThreadEvent encodes a cross-process thread creation into an
// EventBatch using the same "<type>:<uuid>:<json>" ID wire format as
// credential_access / memory findings (EVENT_TYPE_LOG), so it flows through the
// existing ingestion prefix-promotion with no proto change. Returns nil if the
// payload cannot be serialised.
func BuildRemoteThreadEvent(agentID string, payload remoteThreadPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[remote_thread] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("create_remote_thread:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
