// Package hardening runs lightweight CIS-style configuration checks on the
// endpoint and reports the results to the server.
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Check is the result of one hardening assessment item.
type Check struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// Report is the payload sent to the server.
type Report struct {
	Benchmark string  `json:"benchmark"`
	Checks    []Check `json:"checks"`
}

// Reporter periodically runs the hardening checks and sends them to the server.
type Reporter struct {
	serverURL string
	agentID   string
	interval  time.Duration
	client    *http.Client
}

// NewReporter creates a new Reporter.
// interval is how often to report (e.g. 24 * time.Hour).
func NewReporter(serverURL, agentID string, interval time.Duration) *Reporter {
	return &Reporter{
		serverURL: serverURL,
		agentID:   agentID,
		interval:  interval,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Run reports the baseline immediately and then on every interval tick.
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
	checks := Assess()
	if len(checks) == 0 {
		return
	}

	body, err := json.Marshal(Report{Benchmark: BenchmarkName, Checks: checks})
	if err != nil {
		slog.Warn("[hardening] JSONシリアライズ失敗", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/hardening/report", r.serverURL, r.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("[hardening] リクエスト作成失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("[hardening] 送信失敗", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("[hardening] サーバーエラー", "status", resp.StatusCode)
		return
	}

	passed := 0
	for _, c := range checks {
		if c.Passed {
			passed++
		}
	}
	slog.Info("[hardening] ハードニング評価を送信しました", "passed", passed, "total", len(checks))
}
