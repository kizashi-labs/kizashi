package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PlaybookConditions defines what alerts trigger this playbook.
type PlaybookConditions struct {
	MinSeverity    int    `json:"min_severity,omitempty"`
	MaxSeverity    int    `json:"max_severity,omitempty"`
	RuleName       string `json:"rule_name,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	MITRETechnique string `json:"mitre_technique,omitempty"`
	Status         string `json:"status,omitempty"`
}

// PlaybookAction represents a single automated action.
type PlaybookAction struct {
	Type     string `json:"type"`               // isolate_endpoint | create_incident | notify | assign_alert
	Title    string `json:"title,omitempty"`    // for create_incident
	Severity int    `json:"severity,omitempty"` // for create_incident
	Message  string `json:"message,omitempty"`  // for notify
	UserID   string `json:"user_id,omitempty"`  // for assign_alert
}

// Playbook is an automated response workflow.
type Playbook struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description,omitempty"`
	Conditions    PlaybookConditions `json:"conditions"`
	Actions       []PlaybookAction   `json:"actions"`
	IsActive      bool               `json:"is_active"`
	RunCount      int                `json:"run_count"`
	LastRunAt     *time.Time         `json:"last_run_at,omitempty"`
	CreatedBy     *string            `json:"created_by,omitempty"`
	CreatedByName string             `json:"created_by_name,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	// ConfigError is set when the stored conditions or actions could not be
	// decoded. The console path (List/Get) still returns the playbook so an
	// operator can see and repair it — hiding it would leave them unable to fix
	// what they cannot see — while ListActiveForAlert refuses to run it.
	ConfigError string `json:"config_error,omitempty"`
}

// PlaybookRun records a single execution of a playbook.
type PlaybookRun struct {
	ID         string           `json:"id"`
	PlaybookID string           `json:"playbook_id"`
	AlertID    string           `json:"alert_id"`
	ActionsRun []PlaybookAction `json:"actions_run"`
	Success    bool             `json:"success"`
	ErrorMsg   string           `json:"error_msg,omitempty"`
	RanAt      time.Time        `json:"ran_at"`
}

// PlaybookStore manages playbook persistence.
type PlaybookStore struct {
	pool *pgxpool.Pool
}

func NewPlaybookStore(db *DB) *PlaybookStore {
	return &PlaybookStore{pool: db.Pool()}
}

// List returns all playbooks, newest first.
func (s *PlaybookStore) List(ctx context.Context, activeOnly bool) ([]*Playbook, error) {
	where := ""
	if activeOnly {
		where = "WHERE p.is_active = TRUE"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.name, COALESCE(p.description,''),
		       p.conditions, p.actions, p.is_active,
		       p.run_count, p.last_run_at,
		       p.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       p.created_at, p.updated_at
		FROM playbooks p
		LEFT JOIN users u ON u.id = p.created_by
		`+where+`
		ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var playbooks []*Playbook
	for rows.Next() {
		p := &Playbook{}
		var condJSON, actJSON []byte
		var createdBy *string
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description,
			&condJSON, &actJSON, &p.IsActive,
			&p.RunCount, &p.LastRunAt,
			&createdBy, &p.CreatedByName,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			slog.Warn("プレイブックの行を読み取れませんでした（一覧から欠落します）", "error", err)
			continue
		}
		p.ConfigError = decodePlaybookConfig(condJSON, actJSON, &p.Conditions, &p.Actions)
		if p.Actions == nil {
			p.Actions = []PlaybookAction{}
		}
		p.CreatedBy = createdBy
		playbooks = append(playbooks, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("playbooks: 一覧の走査に失敗しました: %w", err)
	}
	if playbooks == nil {
		playbooks = []*Playbook{}
	}
	return playbooks, nil
}

// decodePlaybookConfig decodes the two jsonb blobs and reports, in one string
// an operator can read, whichever of them could not be decoded.
//
// A conditions blob that will not decode leaves the zero value, and the zero
// value means "no filter on anything" — which is why the runner treats it as a
// reason to skip rather than a reason to match. The console needs the opposite
// treatment: it has to show the playbook, or nobody can repair it.
func decodePlaybookConfig(condJSON, actJSON []byte, cond *PlaybookConditions, actions *[]PlaybookAction) string {
	var problems []string
	if err := json.Unmarshal(condJSON, cond); err != nil {
		*cond = PlaybookConditions{}
		problems = append(problems, fmt.Sprintf("条件を解釈できません: %v", err))
	}
	if err := json.Unmarshal(actJSON, actions); err != nil {
		*actions = nil
		problems = append(problems, fmt.Sprintf("アクションを解釈できません: %v", err))
	}
	if len(problems) == 0 {
		return ""
	}
	return strings.Join(problems, " / ") + "（このプレイブックは実行されません）"
}

// Get retrieves a single playbook.
func (s *PlaybookStore) Get(ctx context.Context, id string) (*Playbook, error) {
	p := &Playbook{}
	var condJSON, actJSON []byte
	var createdBy *string
	err := s.pool.QueryRow(ctx, `
		SELECT p.id, p.name, COALESCE(p.description,''),
		       p.conditions, p.actions, p.is_active,
		       p.run_count, p.last_run_at,
		       p.created_by::text,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       p.created_at, p.updated_at
		FROM playbooks p
		LEFT JOIN users u ON u.id = p.created_by
		WHERE p.id = $1`, id,
	).Scan(
		&p.ID, &p.Name, &p.Description,
		&condJSON, &actJSON, &p.IsActive,
		&p.RunCount, &p.LastRunAt,
		&createdBy, &p.CreatedByName,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.ConfigError = decodePlaybookConfig(condJSON, actJSON, &p.Conditions, &p.Actions)
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	p.CreatedBy = createdBy
	return p, nil
}

// Insert creates a new playbook, returning the new ID.
func (s *PlaybookStore) Insert(ctx context.Context, p *Playbook) (string, error) {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return "", err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return "", err
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO playbooks (name, description, conditions, actions, is_active, created_by)
		VALUES ($1, $2, $3, $4, $5, $6::uuid)
		RETURNING id`,
		p.Name, p.Description, string(condJSON), string(actJSON),
		p.IsActive, nilIfEmpty(p.CreatedBy),
	).Scan(&id)
	return id, err
}

// Update replaces a playbook's editable fields.
func (s *PlaybookStore) Update(ctx context.Context, p *Playbook) error {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE playbooks
		SET name=$2, description=$3, conditions=$4, actions=$5, is_active=$6, updated_at=NOW()
		WHERE id=$1`,
		p.ID, p.Name, p.Description, string(condJSON), string(actJSON), p.IsActive,
	)
	return err
}

// Delete removes a playbook.
func (s *PlaybookStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM playbooks WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// SetActive toggles the is_active flag.
func (s *PlaybookStore) SetActive(ctx context.Context, id string, active bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE playbooks SET is_active=$2, updated_at=NOW() WHERE id=$1",
		id, active,
	)
	return err
}

// ListActiveForAlert returns active playbooks whose conditions match the given alert fields.
//
// 読めなかったプレイブックは「条件なし」ではなく「対象外」です。
// 下の各フィルタは MinSeverity > 0 / RuleName != "" のようにゼロ値を
// 「指定なし」として扱うので、conditions の解釈に失敗して cond がゼロ値の
// まま残ると、フィルタが1つも効かず全アラートにマッチします。
// 「重大度9以上、ホスト dc-* のみ」と設定されたプレイブックが、
// 設定を読めなかったというだけで全ホストの全アラートで発火する
// — しかもその1手目が isolate_endpoint でありえます。
func (s *PlaybookStore) ListActiveForAlert(ctx context.Context, severity int, ruleName, hostname, mitreTechnique, status string) ([]*Playbook, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, conditions, actions
		FROM playbooks
		WHERE is_active = TRUE
		ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matched []*Playbook
	var rejected int
	for rows.Next() {
		var id string
		var condJSON, actJSON []byte
		if err := rows.Scan(&id, &condJSON, &actJSON); err != nil {
			rejected++
			slog.Warn("プレイブックの行を読み取れませんでした（このプレイブックは実行されません）",
				"error", err)
			continue
		}
		pb, err := playbookForAlert(id, condJSON, actJSON, severity, ruleName, hostname, mitreTechnique, status)
		if err != nil {
			rejected++
			slog.Error("プレイブックの設定を解釈できないため実行対象から除外しました",
				"playbook", id, "error", err)
			continue
		}
		if pb != nil {
			matched = append(matched, pb)
		}
	}
	// 途中で失敗した反復は短い一致リストを残します。ここを見ないと、
	// 発火すべきプレイブックが黙って実行されません。
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("playbooks: 有効なプレイブックの走査に失敗しました: %w", err)
	}
	if rejected > 0 {
		slog.Warn("設定を読めないプレイブックを実行対象から除外しました",
			"rejected", rejected, "matched", len(matched))
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return matched, nil
}

// playbookForAlert decides what one stored row means for one alert:
// a playbook to run, no match, or a configuration that cannot be read.
//
// The three outcomes are deliberately distinct return values rather than the
// single "nil means no match" the loop used to infer, because two of them used
// to collapse into the third. An undecodable conditions blob left cond at its
// zero value, and matches() reads the zero value as "no filter on anything" —
// so the row that could not be read became the row that matches every alert.
func playbookForAlert(
	id string,
	condJSON, actJSON []byte,
	severity int,
	ruleName, hostname, mitreTechnique, status string,
) (*Playbook, error) {
	var cond PlaybookConditions
	if err := json.Unmarshal(condJSON, &cond); err != nil {
		return nil, fmt.Errorf("条件を解釈できません: %w", err)
	}
	if !cond.matches(severity, ruleName, hostname, mitreTechnique, status) {
		return nil, nil
	}
	// アクションが読めないプレイブックは、アクション0件で実行され、
	// 「成功」として実行ログに残り、run_count も増えます。
	// 何もしていないのに動いているように見える状態です。
	var actions []PlaybookAction
	if err := json.Unmarshal(actJSON, &actions); err != nil {
		return nil, fmt.Errorf("アクションを解釈できません: %w", err)
	}
	return &Playbook{ID: id, Conditions: cond, Actions: actions}, nil
}

// matches applies the condition filters. Every filter treats its zero value as
// "not specified", so the zero-value PlaybookConditions matches everything —
// which is correct for a playbook the operator deliberately left unscoped, and
// catastrophic for one whose scope merely failed to decode. Only the caller can
// tell those apart, so only the caller may construct the conditions.
func (c PlaybookConditions) matches(severity int, ruleName, hostname, mitreTechnique, status string) bool {
	switch {
	case c.MinSeverity > 0 && severity < c.MinSeverity:
		return false
	case c.MaxSeverity > 0 && severity > c.MaxSeverity:
		return false
	case c.RuleName != "" && !containsStr(ruleName, c.RuleName):
		return false
	case c.Hostname != "" && !containsStr(hostname, c.Hostname):
		return false
	case c.MITRETechnique != "" && !containsStr(mitreTechnique, c.MITRETechnique):
		return false
	case c.Status != "" && status != c.Status:
		return false
	}
	return true
}

// RecordRun logs a playbook execution.
func (s *PlaybookStore) RecordRun(ctx context.Context, run *PlaybookRun) error {
	actJSON, err := json.Marshal(run.ActionsRun)
	if err != nil {
		return fmt.Errorf("playbooks: 実行ログのアクション列を書き出せませんでした: %w", err)
	}
	errMsg := run.ErrorMsg
	_, err = s.pool.Exec(ctx, `
		INSERT INTO playbook_runs (playbook_id, alert_id, actions_run, success, error_msg)
		VALUES ($1::uuid, $2, $3, $4, $5)`,
		run.PlaybookID, run.AlertID, string(actJSON), run.Success, errMsg,
	)
	if err != nil {
		return err
	}
	// Increment run counter and update last_run_at
	_, err = s.pool.Exec(ctx,
		"UPDATE playbooks SET run_count=run_count+1, last_run_at=NOW(), updated_at=NOW() WHERE id=$1",
		run.PlaybookID,
	)
	return err
}

// ListRuns returns recent execution history for a playbook.
func (s *PlaybookStore) ListRuns(ctx context.Context, playbookID string, limit int) ([]*PlaybookRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, playbook_id::text, alert_id, actions_run, success, COALESCE(error_msg,''), ran_at
		FROM playbook_runs
		WHERE playbook_id = $1::uuid
		ORDER BY ran_at DESC
		LIMIT $2`, playbookID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*PlaybookRun
	for rows.Next() {
		r := &PlaybookRun{}
		var actJSON []byte
		if err := rows.Scan(&r.ID, &r.PlaybookID, &r.AlertID, &actJSON, &r.Success, &r.ErrorMsg, &r.RanAt); err != nil {
			slog.Warn("プレイブック実行履歴の行を読み取れませんでした（履歴から欠落します）", "error", err)
			continue
		}
		if err := json.Unmarshal(actJSON, &r.ActionsRun); err != nil {
			// nil のまま返すと、その実行は「何のアクションも行わなかった
			// 実行」として履歴に並びます。隔離したのかしていないのかを
			// あとから確かめるための履歴なので、読めなかったことを
			// そのまま返します。
			return nil, fmt.Errorf("playbooks: 実行 %s のアクション列を解釈できませんでした: %w", r.ID, err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("playbooks: 実行履歴の走査に失敗しました: %w", err)
	}
	if runs == nil {
		runs = []*PlaybookRun{}
	}
	return runs, nil
}

// containsStr checks if s contains sub (case-insensitive substring).
func containsStr(s, sub string) bool {
	if len(s) < len(sub) {
		return false
	}
	sl := toLower(s)
	subl := toLower(sub)
	for i := 0; i <= len(sl)-len(subl); i++ {
		if sl[i:i+len(subl)] == subl {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
