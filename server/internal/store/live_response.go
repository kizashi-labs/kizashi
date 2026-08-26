package store

import (
	"context"
	"time"

	"github.com/edr-platform/server/internal/tick"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LiveResponseSession represents an active terminal session on an endpoint.
type LiveResponseSession struct {
	ID           string     `json:"id"`
	AgentID      string     `json:"agent_id"`
	Token        string     `json:"token,omitempty"` // only returned on creation
	Status       string     `json:"status"`
	StartedBy    string     `json:"started_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	LastActivity time.Time  `json:"last_activity"`
}

// LiveResponseCommand represents a single command executed in a session.
type LiveResponseCommand struct {
	ID          string     `json:"id"`
	SessionID   string     `json:"session_id"`
	Input       string     `json:"input"`
	Output      string     `json:"output"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	Status      string     `json:"status"`
	SubmittedBy string     `json:"submitted_by"`
	SubmittedAt time.Time  `json:"submitted_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// LiveResponseStore manages live response sessions and commands.
type LiveResponseStore struct {
	pool *pgxpool.Pool
}

// NewLiveResponseStore creates a new LiveResponseStore.
func NewLiveResponseStore(db *DB) *LiveResponseStore {
	return &LiveResponseStore{pool: db.Pool()}
}

// CreateSession creates a new live response session.
func (s *LiveResponseStore) CreateSession(ctx context.Context, agentID, token, startedBy string) (*LiveResponseSession, error) {
	session := &LiveResponseSession{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO live_response_sessions (agent_id, token, started_by)
		VALUES ($1::uuid, $2, $3)
		RETURNING id, agent_id, token, status, started_by, created_at, closed_at, last_activity
	`, agentID, token, startedBy).Scan(
		&session.ID, &session.AgentID, &session.Token,
		&session.Status, &session.StartedBy,
		&session.CreatedAt, &session.ClosedAt, &session.LastActivity,
	)
	return session, err
}

// GetSessionByToken retrieves a session by its auth token.
func (s *LiveResponseStore) GetSessionByToken(ctx context.Context, token string) (*LiveResponseSession, error) {
	session := &LiveResponseSession{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, token, status, started_by, created_at, closed_at, last_activity
		FROM live_response_sessions
		WHERE token = $1 AND status = 'active'
	`, token).Scan(
		&session.ID, &session.AgentID, &session.Token,
		&session.Status, &session.StartedBy,
		&session.CreatedAt, &session.ClosedAt, &session.LastActivity,
	)
	return session, err
}

// GetSession retrieves a session by ID.
func (s *LiveResponseStore) GetSession(ctx context.Context, sessionID string) (*LiveResponseSession, error) {
	session := &LiveResponseSession{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, token, status, started_by, created_at, closed_at, last_activity
		FROM live_response_sessions
		WHERE id = $1::uuid
	`, sessionID).Scan(
		&session.ID, &session.AgentID, &session.Token,
		&session.Status, &session.StartedBy,
		&session.CreatedAt, &session.ClosedAt, &session.LastActivity,
	)
	return session, err
}

// ListSessions returns all sessions for an agent.
func (s *LiveResponseStore) ListSessions(ctx context.Context, agentID string) ([]*LiveResponseSession, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, token, status, started_by, created_at, closed_at, last_activity
		FROM live_response_sessions
		WHERE agent_id = $1::uuid
		ORDER BY created_at DESC
		LIMIT 20
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*LiveResponseSession
	for rows.Next() {
		session := &LiveResponseSession{}
		if err := rows.Scan(
			&session.ID, &session.AgentID, &session.Token,
			&session.Status, &session.StartedBy,
			&session.CreatedAt, &session.ClosedAt, &session.LastActivity,
		); err != nil {
			continue
		}
		session.Token = "" // don't leak tokens in list
		sessions = append(sessions, session)
	}
	if sessions == nil {
		sessions = []*LiveResponseSession{}
	}
	return sessions, rows.Err()
}

// CloseSession marks a session as closed.
func (s *LiveResponseStore) CloseSession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE live_response_sessions
		SET status = 'closed', closed_at = NOW()
		WHERE id = $1::uuid AND status = 'active'
	`, sessionID)
	return err
}

// TouchSession updates last_activity timestamp.
//
// **落ちると、使用中のセッションが 30 分で期限切れにされます。**
// 呼び出し側が何をするかは呼び出し側が決めます。
//
// `ctx` を使うようになりました。以前は引数を受け取りながら
// `context.Background()` を使っていて、**要求が打ち切られても
// 走り続け、テナントの設定も乗りませんでした。**
func (s *LiveResponseStore) TouchSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE live_response_sessions SET last_activity = NOW() WHERE token = $1
	`, token)
	return err
}

// EnqueueCommand creates a pending command in the session.
func (s *LiveResponseStore) EnqueueCommand(ctx context.Context, sessionID, input, submittedBy string) (*LiveResponseCommand, error) {
	cmd := &LiveResponseCommand{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO live_response_commands (session_id, input, submitted_by)
		VALUES ($1::uuid, $2, $3)
		RETURNING id, session_id, input, output, exit_code, status, submitted_by, submitted_at, completed_at
	`, sessionID, input, submittedBy).Scan(
		&cmd.ID, &cmd.SessionID, &cmd.Input, &cmd.Output,
		&cmd.ExitCode, &cmd.Status, &cmd.SubmittedBy,
		&cmd.SubmittedAt, &cmd.CompletedAt,
	)
	return cmd, err
}

// DequeuePendingCommands returns and marks as running all pending commands for a session.
func (s *LiveResponseStore) DequeuePendingCommands(ctx context.Context, sessionID string) ([]*LiveResponseCommand, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE live_response_commands
		SET status = 'running'
		WHERE session_id = $1::uuid AND status = 'pending'
		RETURNING id, session_id, input, output, exit_code, status, submitted_by, submitted_at, completed_at
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cmds []*LiveResponseCommand
	for rows.Next() {
		cmd := &LiveResponseCommand{}
		if err := rows.Scan(
			&cmd.ID, &cmd.SessionID, &cmd.Input, &cmd.Output,
			&cmd.ExitCode, &cmd.Status, &cmd.SubmittedBy,
			&cmd.SubmittedAt, &cmd.CompletedAt,
		); err != nil {
			continue
		}
		cmds = append(cmds, cmd)
	}
	return cmds, rows.Err()
}

// CompleteCommand records the output of a completed command.
// commandCompletionStatus decides the stored status of a finished command.
//
// **終了コードが 0 でないコマンドは "completed" ではありません。**
//
// エージェントは、コマンドが起動できたなら `hasError=false` を返します ——
// 終了コードが 1 でもです（`agent/internal/response/live_response.go`:
// `return out, exitErr.ExitCode(), false`）。以前サーバはその1つの旗だけを
// 見て `status="completed"` を保存していました。
//
// そして**コンソールは status だけを見ます**
// (`frontend/app/live-response/page.tsx`: `const done = result.status ===
// 'completed'`)。`exit_code` は API の型にも入っていません。
//
// 結果として、`test -f /nonexistent`（終了コード 1、出力なし）は
// **「(出力なし)」が通常の出力として表示されます** —— 担当者はファイルの
// 確認が通ったと読みます。**対応の最中に、失敗が成功に見えます。**
//
// 「起動できなかった」と「起動して失敗した」の区別は、出力と終了コードが
// 持ち続けます。**status が持つべきなのは「成功したか」です。**
func commandCompletionStatus(exitCode int, hasError bool) string {
	if hasError || exitCode != 0 {
		return "error"
	}
	return "completed"
}

func (s *LiveResponseStore) CompleteCommand(ctx context.Context, commandID, output string, exitCode int, hasError bool) error {
	status := commandCompletionStatus(exitCode, hasError)
	_, err := s.pool.Exec(ctx, `
		UPDATE live_response_commands
		SET output = $1, exit_code = $2, status = $3, completed_at = NOW()
		WHERE id = $4::uuid
	`, output, exitCode, status, commandID)
	return err
}

// ListCommands returns all commands for a session, oldest first.
func (s *LiveResponseStore) ListCommands(ctx context.Context, sessionID string) ([]*LiveResponseCommand, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, input, output, exit_code, status, submitted_by, submitted_at, completed_at
		FROM live_response_commands
		WHERE session_id = $1::uuid
		ORDER BY submitted_at ASC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cmds []*LiveResponseCommand
	for rows.Next() {
		cmd := &LiveResponseCommand{}
		if err := rows.Scan(
			&cmd.ID, &cmd.SessionID, &cmd.Input, &cmd.Output,
			&cmd.ExitCode, &cmd.Status, &cmd.SubmittedBy,
			&cmd.SubmittedAt, &cmd.CompletedAt,
		); err != nil {
			continue
		}
		cmds = append(cmds, cmd)
	}
	if cmds == nil {
		cmds = []*LiveResponseCommand{}
	}
	return cmds, rows.Err()
}

// ExpireOldSessions closes sessions inactive for more than 30 minutes.
//
// **返り値がありません。** 呼び出し側に伝える口が無いので、`error` を
// 返すことはできません。落ちると、**閉じたはずのライブレスポンスの
// セッションが `active` のまま残ります** —— 画面には「接続中」が並び、
// トークンも生きています。
//
// 報告先は `tick.Fail` です。**最初は `metrics.BackgroundFailed` に
// しました** ——「回が無い」と思ったからです。呼び出し側を見たら
// `cmd/api/main.go` の5分の ticker で、回が無いのではなく**誰も
// 作っていなかった**だけでした。いまは `tick.Run` で包んであるので、
// 掃除できなかったことが `last_success` に出ます。
func (s *LiveResponseStore) ExpireOldSessions(ctx context.Context) {
	if _, err := s.pool.Exec(ctx, `
		UPDATE live_response_sessions
		SET status = 'expired', closed_at = NOW()
		WHERE status = 'active'
		  AND last_activity < NOW() - INTERVAL '30 minutes'
	`); err != nil {
		tick.Fail(ctx, err,
			"期限切れのライブレスポンスセッションを閉じられませんでした")
	}
}
