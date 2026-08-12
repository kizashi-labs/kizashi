// Package encryption probes endpoint disk-encryption status and reports it to the server.
package encryption

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Status describes the disk-encryption state of an endpoint.
type Status struct {
	Encrypted bool   `json:"encrypted"`
	Method    string `json:"method"`
	Details   string `json:"details"`
}

// Reporter periodically probes disk-encryption status and sends it to the server.
type Reporter struct {
	serverURL string
	agentID   string
	interval  time.Duration
	client    *http.Client
}

// NewReporter creates a new Reporter.
// interval is how often to report (e.g. 12 * time.Hour).
func NewReporter(serverURL, agentID string, interval time.Duration) *Reporter {
	return &Reporter{
		serverURL: serverURL,
		agentID:   agentID,
		interval:  interval,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Run reports encryption status immediately and then on every interval tick.
func (r *Reporter) Run(ctx context.Context) {
	r.report(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.report(ctx)
		}
	}
}

func (r *Reporter) report(ctx context.Context) {
	status := Probe()

	body, err := json.Marshal(status)
	if err != nil {
		slog.Warn("[encryption] JSONシリアライズ失敗", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/encryption/report", r.serverURL, r.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("[encryption] リクエスト作成失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("[encryption] 送信失敗", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("[encryption] サーバーエラー", "status", resp.StatusCode)
		return
	}

	slog.Info("[encryption] 暗号化ステータスを送信しました", "encrypted", status.Encrypted, "method", status.Method)
}
