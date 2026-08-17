// Package response executes server commands on the endpoint.
package response

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

const (
	ackMaxRetries    = 3
	ackRetryBaseWait = time.Second
)

// Executor processes commands received from the EDR server and
// executes the appropriate local response action.
type Executor struct {
	isolation  collector.IsolationManager
	processes  collector.ProcessManager
	quarantine collector.FileQuarantine
	agentID    string
	edrServer  string
	// Ack sends command acknowledgement back to the server
	ack AckSender
}

// AckSender sends command acknowledgements.
type AckSender interface {
	SendAck(ctx context.Context, commandID string, success bool, err string, result []byte) error
}

func NewExecutor(
	isolation collector.IsolationManager,
	processes collector.ProcessManager,
	quarantine collector.FileQuarantine,
	agentID, edrServer string,
	ack AckSender,
) *Executor {
	return &Executor{
		isolation:  isolation,
		processes:  processes,
		quarantine: quarantine,
		agentID:    agentID,
		edrServer:  edrServer,
		ack:        ack,
	}
}

// ─── Command Types ────────────────────────────────────────────

type IsolateCmd struct {
	CommandID  string
	Reason     string
	AlertID    string
	AllowedIPs []string
}

type UnisolateCmd struct {
	CommandID string
	Reason    string
}

type KillProcessCmd struct {
	CommandID   string
	PID         uint32
	ProcessName string
	Reason      string
}

type QuarantineFileCmd struct {
	CommandID string
	Path      string
	Reason    string
	AlertID   string
}

type RestoreFileCmd struct {
	CommandID    string
	QuarantineID string
	RestorePath  string
}

// ─── Handlers ─────────────────────────────────────────────────

// Isolate executes network isolation of this endpoint.
func (e *Executor) Isolate(ctx context.Context, cmd IsolateCmd) {
	slog.Warn("⚠️  エンドポイント隔離を実行中",
		"reason", cmd.Reason,
		"alert_id", cmd.AlertID,
	)

	// Always allow the EDR server IP so we maintain command channel
	allowedIPs := append(cmd.AllowedIPs, extractIP(e.edrServer))

	err := e.isolation.Isolate(allowedIPs, nil)
	if err != nil {
		slog.Error("隔離に失敗しました", "error", err)
		e.ackError(ctx, cmd.CommandID, fmt.Sprintf("isolate failed: %s", err))
		return
	}

	// 終了コード 0 は「ルールが入った」ことを意味しない。適用したつもりで
	// 効いていない場合も、直後に別の何かが流した場合も、ここまでは成功に見える。
	// 実態を読み返してから成功と報告する。隔離は監査・報告の根拠になるので、
	// 確かめずに成功と言うほうが、失敗を報告するより有害になる。
	ok, verr := e.isolation.VerifyIsolation()
	if verr != nil {
		// 状態を確認できなかった。「隔離されていない」とは違うので、そう伝える。
		slog.Error("隔離ルールの確認に失敗しました", "error", verr)
		e.ackError(ctx, cmd.CommandID,
			fmt.Sprintf("isolate applied but verification failed: %s", verr))
		return
	}
	if !ok {
		slog.Error("隔離コマンドは成功しましたが、ルールが見つかりません")
		e.ackError(ctx, cmd.CommandID,
			"isolate reported success but no firewall rules are present")
		return
	}

	slog.Warn("✓ エンドポイントが隔離されました（ルールの存在を確認）",
		"allowed_ips", allowedIPs,
		"reason", cmd.Reason,
	)
	e.ackSuccess(ctx, cmd.CommandID, nil)
}

// Unisolate restores normal network access.
func (e *Executor) Unisolate(ctx context.Context, cmd UnisolateCmd) {
	slog.Info("ネットワーク隔離を解除中", "reason", cmd.Reason)

	if err := e.isolation.Unisolate(); err != nil {
		slog.Error("隔離解除に失敗しました", "error", err)
		e.ackError(ctx, cmd.CommandID, fmt.Sprintf("unisolate failed: %s", err))
		return
	}

	// 解除も同じ。ルールが残ったまま「解除した」と報告すると、コンソール上は
	// 復旧済みなのに端末は繋がらない —— 孤児化した隔離そのものになる。
	// この形は実際に起きており、切り分けに時間を取られた。
	ok, verr := e.isolation.VerifyIsolation()
	if verr != nil {
		slog.Error("隔離解除の確認に失敗しました", "error", verr)
		e.ackError(ctx, cmd.CommandID,
			fmt.Sprintf("unisolate applied but verification failed: %s", verr))
		return
	}
	if ok {
		slog.Error("隔離解除コマンドは成功しましたが、ルールが残っています")
		e.ackError(ctx, cmd.CommandID,
			"unisolate reported success but firewall rules are still present")
		return
	}

	slog.Info("✓ 隔離を解除しました（ルールの消失を確認）")
	e.ackSuccess(ctx, cmd.CommandID, nil)
}

// KillProcess terminates a malicious process.
func (e *Executor) KillProcess(ctx context.Context, cmd KillProcessCmd) {
	slog.Warn("⚠️  プロセス終了を実行中",
		"pid", cmd.PID,
		"process", cmd.ProcessName,
		"reason", cmd.Reason,
	)

	if err := e.processes.Kill(cmd.PID); err != nil {
		slog.Error("プロセス終了に失敗しました", "pid", cmd.PID, "error", err)
		e.ackError(ctx, cmd.CommandID, fmt.Sprintf("kill PID %d: %s", cmd.PID, err))
		return
	}

	slog.Info("✓ プロセスを終了しました", "pid", cmd.PID, "name", cmd.ProcessName)
	e.ackSuccess(ctx, cmd.CommandID, nil)
}

// QuarantineFile moves a suspicious file to quarantine.
func (e *Executor) QuarantineFile(ctx context.Context, cmd QuarantineFileCmd) {
	slog.Warn("⚠️  ファイル隔離を実行中",
		"path", cmd.Path,
		"reason", cmd.Reason,
	)

	// Capture file metadata BEFORE quarantine moves the file. The hash must
	// match what the YARA scanner reported, and `os.Stat` will fail after the
	// move. Failures here are non-fatal — the agent still quarantines, the
	// server just gets a partial record.
	var fileSize int64
	var fileHash string
	if info, err := os.Stat(cmd.Path); err == nil {
		fileSize = info.Size()
	}
	if h, err := hashFileSHA256Pre(cmd.Path); err == nil {
		fileHash = h
	}

	quarantineID, err := e.quarantine.Quarantine(cmd.Path)
	if err != nil {
		slog.Error("ファイル隔離に失敗しました", "path", cmd.Path, "error", err)
		e.ackError(ctx, cmd.CommandID, fmt.Sprintf("quarantine %s: %s", cmd.Path, err))
		return
	}

	slog.Info("✓ ファイルを隔離しました",
		"path", cmd.Path,
		"quarantine_id", quarantineID,
	)

	// Report to server so /quarantine UI can list and offer Restore.
	// quarantine_id is also persisted via the request body so future
	// restore commands can reference the local quarantine entry.
	e.reportQuarantineToServer(ctx, cmd.AlertID, cmd.Path, fileSize, fileHash, quarantineID)

	e.ackSuccess(ctx, cmd.CommandID, []byte(quarantineID))
}

// RestoreFile restores a quarantined file.
func (e *Executor) RestoreFile(ctx context.Context, cmd RestoreFileCmd) {
	slog.Info("ファイルを復元中", "quarantine_id", cmd.QuarantineID)

	if err := e.quarantine.Restore(cmd.QuarantineID, cmd.RestorePath); err != nil {
		slog.Error("ファイル復元に失敗しました", "id", cmd.QuarantineID, "error", err)
		e.ackError(ctx, cmd.CommandID, fmt.Sprintf("restore %s: %s", cmd.QuarantineID, err))
		return
	}

	slog.Info("✓ ファイルを復元しました", "quarantine_id", cmd.QuarantineID)
	e.ackSuccess(ctx, cmd.CommandID, nil)
}

// ─── Helpers ──────────────────────────────────────────────────

func (e *Executor) ackSuccess(ctx context.Context, commandID string, result []byte) {
	e.sendAckWithRetry(ctx, commandID, true, "", result)
}

func (e *Executor) ackError(ctx context.Context, commandID, errMsg string) {
	e.sendAckWithRetry(ctx, commandID, false, errMsg, nil)
}

// sendAckWithRetry sends an ACK with exponential backoff to ensure delivery.
func (e *Executor) sendAckWithRetry(ctx context.Context, commandID string, success bool, errMsg string, result []byte) {
	if e.ack == nil {
		return
	}
	wait := ackRetryBaseWait
	for attempt := 1; attempt <= ackMaxRetries; attempt++ {
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := e.ack.SendAck(tctx, commandID, success, errMsg, result)
		cancel()
		if err == nil {
			return
		}
		slog.Warn("ACK送信失敗、リトライ中",
			"command_id", commandID,
			"attempt", attempt,
			"max", ackMaxRetries,
			"error", err,
		)
		if attempt < ackMaxRetries {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait *= 2
		}
	}
	slog.Error("ACK送信が全試行で失敗しました", "command_id", commandID)
}

func extractIP(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return serverURL
	}
	return u.Hostname()
}

// hashFileSHA256Pre returns the hex SHA-256 of a file. Used pre-quarantine to
// capture the IOC fingerprint before the file is moved out of its original
// path. Best-effort: returns "" on error so reporting can proceed.
func hashFileSHA256Pre(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// reportQuarantineToServer notifies the server that a file has been
// quarantined locally so it appears in /quarantine and can later be
// restored via the UI. Hits the unauthenticated agent-facing endpoint
// /api/v1/agents/:id/quarantine-result (the protected /quarantine POST
// is for human/UI callers). Failures are logged but non-fatal — the
// local quarantine itself already succeeded.
func (e *Executor) reportQuarantineToServer(ctx context.Context, alertID, path string, size int64, hash, quarantineID string) {
	if e.edrServer == "" {
		return
	}
	body, err := json.Marshal(map[string]interface{}{
		"alert_id":      alertID,
		"path":          path,
		"file_size":     size,
		"hash_sha256":   hash,
		"quarantine_id": quarantineID,
	})
	if err != nil {
		slog.Warn("server検疫レポートのJSON生成に失敗", "error", err)
		return
	}
	endpoint := fmt.Sprintf("%s/api/v1/agents/%s/quarantine-result", e.edrServer, e.agentID)
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("server検疫レポートのリクエスト生成に失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("server検疫レポートの送信に失敗", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("server検疫レポートが拒否されました", "status", resp.StatusCode, "path", path)
		return
	}
	slog.Info("✓ server に検疫結果を報告しました", "path", path, "quarantine_id", quarantineID)
}
