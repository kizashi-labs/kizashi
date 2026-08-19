package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// HTTPSender implements HeartbeatSender using the EDR REST API.
// It calls POST /api/v1/agents/:id/heartbeat on the server.
// This is used as a fallback when gRPC is unavailable.
type HTTPSender struct {
	serverURL string
	agentID   string
	client    *http.Client
}

// NewHTTPSender creates an HTTPSender.
// serverURL should be like "http://203.0.113.10:8080".
func NewHTTPSender(serverURL, agentID string) *HTTPSender {
	return &HTTPSender{
		serverURL: serverURL,
		agentID:   agentID,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// FallbackSender tries the primary sender first; on error it falls back to the
// secondary sender. This allows gRPC to be used when available with HTTP as
// a fallback when gRPC connectivity is unavailable.
type FallbackSender struct {
	primary   HeartbeatSender
	secondary HeartbeatSender
}

// NewFallbackSender wraps two senders: primary is tried first, secondary on error.
func NewFallbackSender(primary, secondary HeartbeatSender) *FallbackSender {
	return &FallbackSender{primary: primary, secondary: secondary}
}

func (f *FallbackSender) SendHeartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	resp, err := f.primary.SendHeartbeat(ctx, req)
	if err == nil {
		return resp, nil
	}
	slog.Debug("gRPC heartbeat failed, falling back to HTTP", "error", err)
	return f.secondary.SendHeartbeat(ctx, req)
}

func (s *HTTPSender) SendHeartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	body, err := json.Marshal(map[string]interface{}{
		"hostname":         req.Hostname,
		"ip_addresses":     req.IPAddresses,
		"agent_version":    req.AgentVersion,
		"os_type":          req.OSType,
		"os_version":       req.OSVersion,
		"status":           req.Status,
		"protection_mode":  req.ProtectionMode,
		"telemetry_mode":   req.TelemetryMode,
		"telemetry_detail": req.TelemetryDetail,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/heartbeat", s.serverURL, s.agentID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("heartbeat HTTP %d", resp.StatusCode)
	}

	var hbResp struct {
		ShouldUnisolate bool                    `json:"should_unisolate"`
		ShouldIsolate   bool                    `json:"should_isolate"`
		UninstallGuard  *UninstallGuardMaterial `json:"uninstall_guard"`
	}
	// Best-effort decode — ignore errors (older servers won't have this field).
	_ = json.NewDecoder(resp.Body).Decode(&hbResp)

	return &HeartbeatResponse{
		ShouldUnisolate: hbResp.ShouldUnisolate,
		ShouldIsolate:   hbResp.ShouldIsolate,
		UninstallGuard:  hbResp.UninstallGuard,
	}, nil
}
