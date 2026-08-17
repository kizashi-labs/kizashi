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

const (
	// commandTimeout bounds a single command's runtime.
	commandTimeout = 30 * time.Second
	// waitDelay is how long Run waits after the timeout before force-closing
	// the output pipes and returning, so a grandchild process that inherited
	// them cannot keep the call blocked forever.
	waitDelay = 5 * time.Second
	// maxConcurrentCommands caps commands running at once. A command that
	// hangs for its full timeout occupies one slot; the rest stay available so
	// the session remains usable.
	maxConcurrentCommands = 4
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

	// Commands run in their own goroutine so that one that refuses to die
	// cannot stall the poll loop — previously a single hung command blocked
	// the loop forever and the whole session went silent, including the 401
	// check that ends an expired session. The server hands out each command
	// exactly once (DequeuePendingCommands flips pending→running in a single
	// UPDATE...RETURNING), so running them concurrently cannot double-execute.
	sem := make(chan struct{}, maxConcurrentCommands)

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
				select {
				case sem <- struct{}{}:
					go func(c pendingCommand) {
						defer func() { <-sem }()
						p.executeAndReport(ctx, c)
					}(cmd)
				case <-ctx.Done():
					return
				}
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
	output, exitCode, hasError := p.execute(ctx, cmd.Input)
	// Report on a context of its own: when the session is closed mid-command
	// the parent ctx is already cancelled, and reusing it would discard the
	// output we just collected.
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	p.report(reportCtx, cmd.ID, cmd.Input, output, exitCode, hasError)
}

func (p *LiveResponsePoller) execute(ctx context.Context, input string) (output string, exitCode int, hasError bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, false
	}

	// 30-second timeout per command. Derived from the session context so that
	// closing the session also tears down anything still running.
	cmdCtx, cancel := context.WithTimeout(ctx, commandTimeout)
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
	// Without WaitDelay, Run blocks indefinitely when the killed process
	// leaves a grandchild holding the output pipe — killing the shell does not
	// close a pipe its children inherited, so Wait never returns even though
	// cmdCtx expired. WaitDelay force-closes the pipes and gives up.
	c.WaitDelay = waitDelay

	err := c.Run()
	out := buf.String()
	if cmdCtx.Err() != nil {
		out += fmt.Sprintf("\n[コマンドを中断しました: %v]", cmdCtx.Err())
	}
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
