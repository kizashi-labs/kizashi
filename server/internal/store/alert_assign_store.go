package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertAssignRule mirrors the alert_assign_rules table.
type AlertAssignRule struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Priority   int             `json:"priority"`
	Conditions json.RawMessage `json:"conditions"`
	AssigneeID string          `json:"assignee_id"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

// alertAssignConditions is the shape stored in the conditions JSONB column.
type alertAssignConditions struct {
	SeverityMatch []string `json:"severity_match,omitempty"`
	RuleIDMatch   []string `json:"rule_id_match,omitempty"`
}

// AlertAssignRuleStore handles database operations for alert auto-assignment rules.
type AlertAssignRuleStore struct {
	pool *pgxpool.Pool
}

// NewAlertAssignRuleStore creates a new AlertAssignRuleStore.
func NewAlertAssignRuleStore(pool *pgxpool.Pool) *AlertAssignRuleStore {
	return &AlertAssignRuleStore{pool: pool}
}

const assignRuleSelectCols = `id, name, priority, conditions, assignee_id::text, enabled, created_at, updated_at`

func scanAssignRule(row interface {
	Scan(dest ...interface{}) error
}) (*AlertAssignRule, error) {
	var r AlertAssignRule
	var createdAt, updatedAt time.Time
	var condRaw []byte
	err := row.Scan(
		&r.ID, &r.Name, &r.Priority, &condRaw, &r.AssigneeID,
		&r.Enabled, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	r.UpdatedAt = updatedAt.Format(time.RFC3339)
	if condRaw != nil {
		r.Conditions = json.RawMessage(condRaw)
	} else {
		r.Conditions = json.RawMessage(`{}`)
	}
	return &r, nil
}

// List returns all alert assignment rules ordered by priority descending.
func (s *AlertAssignRuleStore) List(ctx context.Context) ([]*AlertAssignRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM alert_assign_rules ORDER BY priority DESC, created_at`, assignRuleSelectCols))
	if err != nil {
		return nil, fmt.Errorf("alert_assign_rules list: %w", err)
	}
	defer rows.Close()

	var rules []*AlertAssignRule
	for rows.Next() {
		r, err := scanAssignRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*AlertAssignRule{}
	}
	return rules, nil
}

// CreateAssignRuleInput holds fields for creating a new assignment rule.
type CreateAssignRuleInput struct {
	Name       string
	Priority   int
	Conditions json.RawMessage
	AssigneeID string
	Enabled    bool
}

// Create inserts a new alert assignment rule.
func (s *AlertAssignRuleStore) Create(ctx context.Context, in CreateAssignRuleInput) (*AlertAssignRule, error) {
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`INSERT INTO alert_assign_rules (name, priority, conditions, assignee_id, enabled)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING %s`, assignRuleSelectCols),
		in.Name, in.Priority, []byte(cond), in.AssigneeID, in.Enabled,
	)
	r, err := scanAssignRule(row)
	if err != nil {
		return nil, fmt.Errorf("alert_assign_rules create: %w", err)
	}
	return r, nil
}

// UpdateAssignRuleInput holds fields for updating an assignment rule.
type UpdateAssignRuleInput struct {
	Name       string
	Priority   int
	Conditions json.RawMessage
	AssigneeID string
	Enabled    bool
}

// Update modifies an existing alert assignment rule.
func (s *AlertAssignRuleStore) Update(ctx context.Context, id string, in UpdateAssignRuleInput) (*AlertAssignRule, error) {
	cond := in.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage(`{}`)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`UPDATE alert_assign_rules
		 SET name = $2, priority = $3, conditions = $4, assignee_id = $5, enabled = $6, updated_at = NOW()
		 WHERE id = $1
		 RETURNING %s`, assignRuleSelectCols),
		id, in.Name, in.Priority, []byte(cond), in.AssigneeID, in.Enabled,
	)
	r, err := scanAssignRule(row)
	if err != nil {
		return nil, fmt.Errorf("alert_assign_rules update: %w", err)
	}
	return r, nil
}

// Delete removes an alert assignment rule by ID.
func (s *AlertAssignRuleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alert_assign_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("alert_assign_rules delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("alert_assign_rule not found: %s", id)
	}
	return nil
}

// FindMatch queries enabled rules ordered by priority and returns the first rule
// whose conditions match the given alertSeverity and ruleID.
// Returns (assigneeID, true) on match, or ("", false) when no rule matches.
func (s *AlertAssignRuleStore) FindMatch(ctx context.Context, alertSeverity, ruleID string) (assigneeID string, found bool) {
	rows, err := s.pool.Query(ctx, `
		SELECT assignee_id::text, conditions
		FROM alert_assign_rules
		WHERE enabled = true
		ORDER BY priority DESC
	`)
	if err != nil {
		return "", false
	}
	defer rows.Close()

	for rows.Next() {
		var aid string
		var condRaw []byte
		if err := rows.Scan(&aid, &condRaw); err != nil {
			continue
		}

		var cond alertAssignConditions
		if len(condRaw) > 0 {
			if err := json.Unmarshal(condRaw, &cond); err != nil {
				// 条件が読めない割り当てルールを黙って飛ばすと、その
				// ルールは存在しないのと同じになります。担当者が付かない
				// アラートが出続けても、原因はどこにも出ません。
				// この関数は (string, bool) しか返せないので、記録します。
				slog.Error("割り当てルールの条件を読めませんでした。このルールは適用されません",
					"assignee", aid, "error", err)
				continue
			}
		}

		// Empty conditions means match-all.
		severityOK := len(cond.SeverityMatch) == 0
		for _, s := range cond.SeverityMatch {
			if s == alertSeverity {
				severityOK = true
				break
			}
		}

		ruleOK := len(cond.RuleIDMatch) == 0
		for _, r := range cond.RuleIDMatch {
			if r == ruleID {
				ruleOK = true
				break
			}
		}

		if severityOK && ruleOK {
			return aid, true
		}
	}
	// 途中で失敗した反復は、優先度の低いルールを見ないまま「該当なし」に
	// なります。この関数にエラー戻り値は無いので、せめて記録は残します。
	// 黙って未割り当てになったアラートは、誰も待っていないことに誰も
	// 気づけません。
	if err := rows.Err(); err != nil {
		slog.Warn("alert_assign_rules: ルールの走査に失敗しました。"+
			"このアラートは自動割り当てされません",
			"severity", alertSeverity, "rule_id", ruleID, "error", err)
		return "", false
	}
	return "", false
}
