// Package response — live response polling client.
// When the server starts a live response session, it sends a collect_artifact
// command with type=LOGS and the target field containing a JSON LiveResponseStartPayload.
// This module starts an HTTP polling goroutine that fetches and executes commands.
package response

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// LiveResponseStartPayload is the JSON carried in the collect_artifact target field.
type LiveResponseStartPayload struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	Token       string `json:"token"`
	CallbackURL string `json:"callback_url"` // e.g. "https://edr-server/api/v1"
}

// LiveResponsePoller polls the server for commands and executes them.
type LiveResponsePoller struct {
	payload    LiveResponseStartPayload
	httpClient *http.Client
	cancel     context.CancelFunc
}

// StartLiveResponse begins a live response polling loop in the background.
func StartLiveResponse(ctx context.Context, payload LiveResponseStartPayload) *LiveResponsePoller {
	ctx, cancel := context.WithCancel(ctx)
	p := &LiveResponsePoller{
		payload: payload,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		cancel: cancel,
	}
	go p.run(ctx)
	slog.Info("ライブレスポンスセッション開始", "session", payload.SessionID)
	return p
}

// Stop cancels the polling loop.
func (p *LiveResponsePoller) Stop() {
	p.cancel()
}

func (p *LiveResponsePoller) run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("ライブレスポンスセッション終了", "session", p.payload.SessionID)
			return
		case <-ticker.C:
			cmds, err := p.poll(ctx)
			if err != nil {
				slog.Debug("live response poll failed", "error", err)
				continue
			}
			for _, cmd := range cmds {
				p.executeAndReport(ctx, cmd)
			}
		}
	}
}

type pendingCommand struct {
	ID    string `json:"id"`
	Input string `json:"input"`
}

type pollResponse struct {
	Commands []pendingCommand `json:"commands"`
}

func (p *LiveResponsePoller) poll(ctx context.Context) ([]pendingCommand, error) {
	url := fmt.Sprintf("%s/live-response/poll?token=%s", p.payload.CallbackURL, p.payload.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		p.cancel() // session ended or token expired
		return nil, fmt.Errorf("session expired")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("poll returned %d", resp.StatusCode)
	}

	var pr pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	return pr.Commands, nil
}

func (p *LiveResponsePoller) executeAndReport(ctx context.Context, cmd pendingCommand) {
	output, exitCode, hasError := p.execute(cmd.Input)
	p.report(ctx, cmd.ID, cmd.Input, output, exitCode, hasError)
}

func (p *LiveResponsePoller) execute(input string) (output string, exitCode int, hasError bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, false
	}

	// 30-second timeout per command
	cmdCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(cmdCtx, "cmd.exe", "/C", input)
	} else {
		c = exec.CommandContext(cmdCtx, "/bin/sh", "-c", input)
	}

	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf

	err := c.Run()
	out := buf.String()
	// Truncate to 64KB to avoid overwhelming the server
	if len(out) > 64*1024 {
		out = out[:64*1024] + "\n[出力が切り捨てられました]"
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.ExitCode(), false
		}
		return out + "\n" + err.Error(), 1, true
	}
	return out, 0, false
}

func (p *LiveResponsePoller) report(ctx context.Context, cmdID, input, output string, exitCode int, hasError bool) {
	body, _ := json.Marshal(map[string]interface{}{
		"command_id": cmdID,
		"input":      input,
		"output":     output,
		"exit_code":  exitCode,
		"error":      hasError,
	})

	url := fmt.Sprintf("%s/live-response/output?token=%s", p.payload.CallbackURL, p.payload.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("live response report: create request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		slog.Warn("live response report: send failed", "error", err)
		return
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
}
