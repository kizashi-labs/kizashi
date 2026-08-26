package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/edr-platform/agent/internal/tamper"
	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BuildTamperEvent encodes a self-protection finding into an EventBatch using the
// same "<type>:<uuid>:<json>" ID wire format as eventlog_cleared /
// credential_access (EVENT_TYPE_LOG), so it flows through the existing ingestion
// prefix-promotion with no proto change. Returns nil on serialise error.
//
// The payload type lives in internal/tamper rather than here because the watchdog
// produces findings too and must not link the proto. See that package's doc.
func BuildTamperEvent(agentID string, payload tamper.Payload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[tamper] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("tamper:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
