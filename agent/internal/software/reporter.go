// Package software collects installed software inventory and reports it to the server.
package software

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Reporter periodically collects and sends software inventory to the server.
type Reporter struct {
	serverURL string
	agentID   string
	interval  time.Duration
	client    *http.Client
}

// NewReporter creates a new Reporter.
// interval is how often to report (e.g. 6 * time.Hour).
func NewReporter(serverURL, agentID string, interval time.Duration) *Reporter {
	return &Reporter{
		serverURL: serverURL,
		agentID:   agentID,
		interval:  interval,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Run reports software inventory immediately and then on every interval tick.
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
	entries := Collect()
	if len(entries) == 0 {
		return
	}

	body, err := json.Marshal(map[string]interface{}{
		"software": entries,
	})
	if err != nil {
		slog.Warn("[software] JSONシリアライズ失敗", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/software/report", r.serverURL, r.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("[software] リクエスト作成失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("[software] 送信失敗", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("[software] サーバーエラー", "status", resp.StatusCode)
		return
	}

	slog.Info("[software] インベントリを送信しました", "count", len(entries))
}
