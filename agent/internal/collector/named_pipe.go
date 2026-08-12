package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// namedPipePayload is the JSON carried by a pipe_created event: a named pipe was
// created/opened on the host. C2 frameworks (Cobalt Strike, and its many clones)
// use predictably-named SMB named pipes for beacon peer-to-peer linking and post-
// exploitation (\msagent_##, \postex_####, \status_##, \mojo.####, …), so the pipe
// NAME is the load-bearing indicator. Sysmon reports this as EventID 17 (PipeEvent
// - Created) with fields PipeName + Image; the SigmaHQ `pipe_created` category
// rules (incl. the shipped "Cobalt Strike Beacon via Named Pipe", severity 9 /
// auto-isolate) select on PipeName. PipeName is the sole field that rule matches on;
// Image is emitted best-effort for the many other pipe rules that combine the two.
type namedPipePayload struct {
	PipeName string `json:"pipe_name"`  // Sysmon-style pipe name, e.g. \msagent_5x
	Image    string `json:"image_path"` // creating process image (best-effort)
	PID      int    `json:"pid"`
}

// NamedPipePayload constructs the payload for a pipe_created event.
func NamedPipePayload(pipeName, image string, pid int) namedPipePayload {
	return namedPipePayload{
		PipeName: pipeName,
		Image:    image,
		PID:      pid,
	}
}

// BuildNamedPipeEvent encodes a named-pipe creation into an EventBatch using the
// same "<type>:<uuid>:<json>" ID wire format as create_remote_thread / ps_module
// (EVENT_TYPE_LOG), so it flows through the existing ingestion prefix-promotion
// with no proto change. Returns nil if the payload cannot be serialised.
func BuildNamedPipeEvent(agentID string, payload namedPipePayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[pipe_created] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("pipe_created:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
