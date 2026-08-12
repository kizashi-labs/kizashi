package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// credAccessPayload is the JSON carried by a credential_access event — one
// process reading another process's memory. On Windows this is a PROCESS_VM_READ
// open of lsass.exe (LSASS-memory read used by credential dumpers, T1003.001); on
// Linux it is an eBPF LSM ptrace_access_check hit (gdb -p, /proc/<pid>/mem,
// process_vm_readv, ptrace — T1003/T1055). The server's detection engine turns it
// into an alert. target_image identifies what was accessed (lsass.exe on Windows,
// the target process comm on Linux) — do not hard-code it.
type credAccessPayload struct {
	TargetPID   int    `json:"target_pid"`   // accessed process PID (lsass on Windows)
	TargetImage string `json:"target_image"` // accessed process image/comm
	SourcePID   int    `json:"source_pid"`   // the accessing process
	SourceImage string `json:"source_image"` // accessor image base name (best-effort)
	AccessMask  string `json:"access_mask"`  // DesiredAccess (Win) or "ptrace_mode=0x.." (Linux)
	Enforced    bool   `json:"enforced"`     // true = access was stripped/denied
}

// CredentialAccessPayload constructs the payload for a credential_access event.
// targetImage is the accessed process ("lsass.exe" on Windows, the target comm on
// Linux) — the detection engine relies on it to label and platform-branch.
func CredentialAccessPayload(targetPID int, targetImage string, sourcePID int, sourceImage, accessMask string, enforced bool) credAccessPayload {
	return credAccessPayload{
		TargetPID:   targetPID,
		TargetImage: targetImage,
		SourcePID:   sourcePID,
		SourceImage: sourceImage,
		AccessMask:  accessMask,
		Enforced:    enforced,
	}
}

// BuildCredentialAccessEvent encodes a credential_access decision into an
// EventBatch using the same "credential_access:<uuid>:<json>" ID wire format as
// process_block / memory findings (EVENT_TYPE_LOG), so it flows through the
// existing ingestion prefix-promotion with no proto change. Returns nil if the
// payload cannot be serialised.
func BuildCredentialAccessEvent(agentID string, payload credAccessPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[credential_access] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("credential_access:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
