package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ResponseAction represents a recorded response action against an agent.
type ResponseAction struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	ActionType  string `json:"action_type"`
	Status      string `json:"status"`
	TriggeredBy string `json:"triggered_by"`
	// TriggeredByName is the resolved user display name (full_name/email) when
	// executed_by is a user UUID. Empty for agent/system actions or unknown
	// users — the UI falls back accordingly.
	TriggeredByName string          `json:"triggered_by_name,omitempty"`
	TriggeredAt     time.Time       `json:"triggered_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	Error           *string         `json:"error,omitempty"`
	Details         json.RawMessage `json:"details,omitempty"`
}

// ResponseActionStore handles persistence of response actions.
type ResponseActionStore struct {
	pool *pgxpool.Pool
}

// NewResponseActionStore creates a new ResponseActionStore.
func NewResponseActionStore(db *DB) *ResponseActionStore {
	return &ResponseActionStore{pool: db.Pool()}
}

// 対応アクションの状態。migration 379 の CHECK 制約と対応する。
//
// success を直接書く手段は無い（DB 側で status_text から導出される生成列）。
// 記録したい事実がどれなのかを、呼び出し側が必ず選ぶことになる。
const (
	// StatusPending は受理したがまだ送っていない状態。
	StatusPending = "pending"
	// StatusDispatched はエージェントへ送出した状態。結果はまだ分からない。
	// 送れたことと実行できたことは別なので、ここを success にしてはいけない。
	StatusDispatched = "dispatched"
	// StatusRunning はエージェントが実行中と報告した状態。
	StatusRunning = "running"
	// StatusSuccess は完了した状態。
	StatusSuccess = "success"
	// StatusFailure は失敗した状態。
	StatusFailure = "failure"
	// StatusTimeout は送ったが期限内に結果が返らなかった状態。
	// failure と分けるのは、ネットワーク断とエージェントの拒否では
	// 復旧手順が違うため。
	StatusTimeout = "timeout"
	// StatusWarning は完了したが注意すべき結果（スキャンで検出あり等）。
	StatusWarning = "warning"
	// StatusCancelled は利用者またはエージェントが中止した状態。
	StatusCancelled = "cancelled"
	// StatusSuppressed は安全弁が「実行しない」と判断した状態（migration 431）。
	// failure でも cancelled でもない: 失敗したのではなく、実行しないことが
	// 正しい動作だった。どの安全弁が止めたかは details.outcome に入る。
	StatusSuppressed = "suppressed"
)

// Record inserts a response action record and returns its id.
//
// status には「いま確実に言えること」を渡すこと。コマンドを送っただけなら
// StatusDispatched であって StatusSuccess ではない。終了状態が判明したら
// 返り値の id を使って Complete で更新する。
func (s *ResponseActionStore) Record(ctx context.Context, agentID, actionType, status, triggeredBy string, details interface{}) (string, error) {
	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			// 対応内容を落として記録だけ残すと、あとから「何をしたか」が
			// 分からない対応履歴になります。
			return "", fmt.Errorf("対応内容を記録用に変換できませんでした: %w", err)
		}
	}
	if status == "" {
		status = StatusPending
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO response_actions
		  (agent_id, action_type, executed_by, status_text, details)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, agentID, actionType, triggeredBy, status, detailsJSON).Scan(&id)
	return id, err
}

// Complete updates a response action to its terminal state.
//
// エージェントからの結果通知や、期限切れを検出したワーカーから呼ぶ。
// errMsg は失敗時の理由。空文字なら記録しない。
func (s *ResponseActionStore) Complete(ctx context.Context, id, status, errMsg string) error {
	var errPtr *string
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE response_actions
		   SET status_text = $2,
		       error_msg   = COALESCE($3, error_msg)
		 WHERE id = $1
	`, id, status, errPtr)
	return err
}

// RecordFailure records a response action that could NOT be dispatched, together
// with the reason.
//
// Record's status argument was previously passed the literal "success" by every
// dispatch handler, so the audit trail said success even when the command never
// left the server. It is also the only writer of response_actions, and it never
// populated error_msg — the column existed with nothing to put in it. An audit
// trail that always says success is worse than none: it gets cited as evidence
// that a containment action happened.
func (s *ResponseActionStore) RecordFailure(ctx context.Context, agentID, actionType, triggeredBy, errMsg string, details interface{}) error {
	var detailsJSON []byte
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			detailsJSON = b
		}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO response_actions
		  (agent_id, action_type, executed_by, status_text, details, error_msg)
		VALUES ($1, $2, $3, 'failure', $4, $5)
	`, agentID, actionType, triggeredBy, detailsJSON, errMsg)
	return err
}

// ExpireStale moves response actions that never reached a terminal state to
// StatusTimeout, and returns how many rows were changed.
//
// エージェントが死ぬ・NATS が詰まる・コマンドが握り潰される、といった場合に
// 行は dispatched のまま永遠に残る。UI 上は「実行中」に見え続けるので、
// 操作者は隔離が効いていると思い込む。放置された記録は、失敗したことすら
// 分からない記録であり、対応の証拠としては最も質が悪い。
//
// olderThan は executed_at からの経過時間。ここで failure ではなく timeout を
// 付けるのは、「結果が返らなかった」と「エージェントが拒否した」を混ぜないため。
// 前者は再送で解決することがあり、後者はしない。
func (s *ResponseActionStore) ExpireStale(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE response_actions
		   SET status_text = $1,
		       error_msg   = COALESCE(error_msg,
		                              '結果が返らないまま期限切れになりました')
		 WHERE status_text IN ($2, $3, $4)
		   AND executed_at < NOW() - $5::interval
	`, StatusTimeout, StatusPending, StatusDispatched, StatusRunning,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// List returns paginated response actions for an agent, newest first.
func (s *ResponseActionStore) List(ctx context.Context, agentID string, limit, offset int) ([]*ResponseAction, int, error) {
	var total int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM response_actions WHERE agent_id = $1`, agentID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// LEFT JOIN users to resolve executed_by (a user UUID) to a display name.
	// executed_by may also be a non-UUID like "agent"/"admin"; the text-cast
	// comparison simply yields no match and triggered_by_name stays empty.
	rows, err := s.pool.Query(ctx, `
		SELECT ra.id, ra.agent_id, ra.action_type,
		       ra.status_text,
		       ra.executed_by, ra.executed_at, ra.executed_at, ra.error_msg, ra.details,
		       COALESCE(NULLIF(u.full_name, ''), u.email, '')
		FROM response_actions ra
		LEFT JOIN users u ON u.id::text = ra.executed_by
		WHERE ra.agent_id = $1
		ORDER BY ra.executed_at DESC
		LIMIT $2 OFFSET $3
	`, agentID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var actions []*ResponseAction
	for rows.Next() {
		a := &ResponseAction{}
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.ActionType, &a.Status, &a.TriggeredBy,
			&a.TriggeredAt, &a.CompletedAt, &a.Error, &a.Details, &a.TriggeredByName,
		); err != nil {
			continue
		}
		actions = append(actions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if actions == nil {
		actions = []*ResponseAction{}
	}
	return actions, total, nil
}

// RecentContainment reports whether a containment command was actually
// dispatched to this agent within the given window.
//
// It exists so the detection engines can tell "the endpoint's firewall just
// changed because WE changed it" from "the endpoint's firewall just changed and
// we have no idea why". Only StatusDispatched counts: a suppressed or failed
// isolation never reached the endpoint, so it cannot explain anything observed
// there. See detection.SelfRemediationSuppressor.
func (s *ResponseActionStore) RecentContainment(ctx context.Context, agentID string, within time.Duration) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM response_actions
			WHERE agent_id = $1::uuid
			  AND action_type IN ('isolate', 'unisolate')
			  AND status_text = $2
			  AND executed_at > NOW() - $3::interval
		)`, agentID, StatusDispatched, within.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("直近の封じ込め操作の照会に失敗しました: %w", err)
	}
	return exists, nil
}
