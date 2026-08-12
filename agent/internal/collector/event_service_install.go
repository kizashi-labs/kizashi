package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// serviceInstallPayload is the JSON carried by a service_installed event: a
// Windows service was installed (System EventID 7045). Installing a service is
// the classic PsExec / Cobalt Strike lateral-movement + persistence primitive
// (T1543.003); the server decides maliciousness from the ImagePath shape.
type serviceInstallPayload struct {
	ServiceName string `json:"service_name"`
	ImagePath   string `json:"image_path"`
	ServiceType string `json:"service_type"`
	StartType   string `json:"start_type"`
	Account     string `json:"account"`
}

// ServiceInstallPayload constructs the payload for a service_installed event.
func ServiceInstallPayload(name, imagePath, serviceType, startType, account string) serviceInstallPayload {
	return serviceInstallPayload{
		ServiceName: name,
		ImagePath:   imagePath,
		ServiceType: serviceType,
		StartType:   startType,
		Account:     account,
	}
}

// BuildServiceInstallEvent encodes a service installation into an EventBatch
// using the same "<type>:<uuid>:<json>" ID wire format as pipe_created /
// create_remote_thread (EVENT_TYPE_LOG), so it flows through the existing
// ingestion prefix-promotion with no proto change. Returns nil on serialise error.
func BuildServiceInstallEvent(agentID string, payload serviceInstallPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[service_installed] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("service_installed:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
