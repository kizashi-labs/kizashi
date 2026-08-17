package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleStore handles detection rule database operations.
type RuleStore struct {
	pool *pgxpool.Pool
}

func NewRuleStore(db *DB) *RuleStore {
	return &RuleStore{pool: db.Pool()}
}

// RuleRow mirrors the rules table.
type RuleRow struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Type              string    `json:"type"`
	Platform          []string  `json:"platform"`
	Severity          int       `json:"severity"`
	Content           string    `json:"content"`
	Enabled           bool      `json:"enabled"`
	Source            string    `json:"source"`
	MITRETags         []string  `json:"mitre_tags"`
	AutoIsolate       bool      `json:"auto_isolate"`
	AutoKill          bool      `json:"auto_kill"`
	AutoQuarantine    bool      `json:"auto_quarantine"`
	Description       *string   `json:"description,omitempty"`
	FalsePositiveRate float64   `json:"false_positive_rate"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// RuleFilter defines filters for listing rules.
type RuleFilter struct {
	Type    string
	Enabled *bool
	Search  string
	Limit   int
	Offset  int
}

// ListEnabled returns all enabled detection rules.
// ruleListWhere builds the WHERE clause and arguments for List.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 検査ファイルには同じ組み立ての写しが置いてあり、そちらだけが試されて
// いました。公開はしません —— `List` からしか使わないので、公開すると
// `TestStoreSymbolsAreReachable` の数が増えます。
func ruleListWhere(filter RuleFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	// プレースホルダの番号は args の本数から出します。
	//
	// **別にカウンタを持つと、条件を足したときに片方だけ増やせてしまいます。**
	// 実際、最後の `i++` は誰も読まないまま残っていました（golangci-lint の
	// ineffassign が見つけました）。番号と引数がずれると、SQL は通って
	// 結果だけが違うので、いちばん気づきにくい形です。
	ph := func() string { return fmt.Sprintf("$%d", len(args)+1) }

	if filter.Type != "" {
		conditions = append(conditions, "type = "+ph())
		args = append(args, filter.Type)
	}
	if filter.Enabled != nil {
		conditions = append(conditions, "enabled = "+ph())
		args = append(args, *filter.Enabled)
	}
	if filter.Search != "" {
		p := ph() // 2か所で同じ番号を使うので、append の前に取ります。
		conditions = append(conditions, fmt.Sprintf("(name ILIKE %s OR description ILIKE %s)", p, p))
		args = append(args, "%"+filter.Search+"%")
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	return where, args
}

func (s *RuleStore) ListEnabled(ctx context.Context) ([]*RuleRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, platform, severity, content,
			   enabled, source, mitre_tags,
			   auto_isolate, auto_kill, auto_quarantine,
			   description, false_positive_rate, created_at, updated_at
		FROM rules
		WHERE enabled = true
		ORDER BY severity DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Type, &r.Platform, &r.Severity, &r.Content,
			&r.Enabled, &r.Source, &r.MITRETags,
			&r.AutoIsolate, &r.AutoKill, &r.AutoQuarantine,
			&r.Description, &r.FalsePositiveRate, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		rules = append(rules, &r)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// List returns rules with optional filtering and pagination.
func (s *RuleStore) List(ctx context.Context, filter RuleFilter) ([]*RuleRow, int, error) {
	where, args := ruleListWhere(filter)
	i := len(args) + 1

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM rules "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	listQuery := `
		SELECT id, name, type, platform, severity, content,
			   enabled, source, mitre_tags,
			   auto_isolate, auto_kill, auto_quarantine,
			   description, false_positive_rate, created_at, updated_at
		FROM rules ` + where + `
		ORDER BY severity DESC, name
		LIMIT $` + fmt.Sprintf("%d", i) + ` OFFSET $` + fmt.Sprintf("%d", i+1)

	args = append(args, limit, filter.Offset)
	rows, err := s.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []*RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Type, &r.Platform, &r.Severity, &r.Content,
			&r.Enabled, &r.Source, &r.MITRETags,
			&r.AutoIsolate, &r.AutoKill, &r.AutoQuarantine,
			&r.Description, &r.FalsePositiveRate, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			continue
		}
		rules = append(rules, &r)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return rules, total, nil
}

// Get retrieves a single rule by ID.
func (s *RuleStore) Get(ctx context.Context, id string) (*RuleRow, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, type, platform, severity, content,
			   enabled, source, mitre_tags,
			   auto_isolate, auto_kill, auto_quarantine,
			   description, false_positive_rate, created_at, updated_at
		FROM rules WHERE id = $1`, id)

	var r RuleRow
	err := row.Scan(
		&r.ID, &r.Name, &r.Type, &r.Platform, &r.Severity, &r.Content,
		&r.Enabled, &r.Source, &r.MITRETags,
		&r.AutoIsolate, &r.AutoKill, &r.AutoQuarantine,
		&r.Description, &r.FalsePositiveRate, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// normalizeMITRETags converts raw Sigma tags into ATT&CK technique IDs and drops
// everything that is not a technique.
//
// mitre_tags is compared by exact string on the scoring and attribution paths, so
// "attack.t1059.004" does NOT match "T1059.004": a rule stored that way fires but
// contributes nothing to technique attribution, and its alerts can end up with a
// TACTIC name ("attack.execution") in mitre_technique. Found live 2026-08-03 on 25
// enabled rules — silent, because the rule works and only the attribution is lost.
//
// Normalizing here rather than only in each caller means it holds for every write
// path. The SigmaHQ importer already normalizes, so this is a no-op for it; the
// paths that did not are exactly the ones that produced those 25 rows.
//
// Order is preserved: the first technique tag is treated as a rule's primary
// technique (see detection/sigma_builtins.go), so reordering changes meaning.
// Duplicates created by normalization collapse onto their first occurrence.
func normalizeMITRETags(tags []string) []string {
	if len(tags) == 0 {
		return tags
	}
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		norm := tag
		switch {
		case techniqueTagRe.MatchString(lower):
			norm = strings.ToUpper(strings.TrimPrefix(lower, "attack."))
		case strings.HasPrefix(lower, "attack."):
			// A tactic/group/software tag. Not a technique, so it must not sit in a
			// field whose consumers assume technique IDs.
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

// techniqueTagRe matches Sigma technique tags such as "attack.t1059" and
// "attack.t1059.004".
var techniqueTagRe = regexp.MustCompile(`^attack\.t[0-9]{4}(\.[0-9]{3})?$`)

// Create inserts a new rule.
func (s *RuleStore) Create(ctx context.Context, r *RuleRow) error {
	r.MITRETags = normalizeMITRETags(r.MITRETags)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rules (
			id, name, type, platform, severity, content,
			enabled, source, mitre_tags,
			auto_isolate, auto_kill, auto_quarantine,
			description, false_positive_rate, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())`,
		r.ID, r.Name, r.Type, r.Platform, r.Severity, r.Content,
		r.Enabled, r.Source, r.MITRETags,
		r.AutoIsolate, r.AutoKill, r.AutoQuarantine,
		r.Description, r.FalsePositiveRate,
	)
	return err
}

// Update updates an existing rule.
func (s *RuleStore) Update(ctx context.Context, r *RuleRow) error {
	r.MITRETags = normalizeMITRETags(r.MITRETags)
	_, err := s.pool.Exec(ctx, `
		UPDATE rules SET
			name              = $2,
			type              = $3,
			platform          = $4,
			severity          = $5,
			content           = $6,
			enabled           = $7,
			-- Preserve the quarantined⟹disabled invariant (migration 292): editing a
			-- quarantined rule with enabled=true lifts the quarantine rather than
			-- leaving an enabled+quarantined row the CHECK constraint would reject.
			curate_state      = CASE WHEN $7 AND curate_state = 'quarantined' THEN 'enabled' ELSE curate_state END,
			source            = $8,
			mitre_tags        = $9,
			auto_isolate      = $10,
			auto_kill         = $11,
			auto_quarantine   = $12,
			description       = $13,
			false_positive_rate = $14,
			updated_at        = NOW()
		WHERE id = $1`,
		r.ID, r.Name, r.Type, r.Platform, r.Severity, r.Content,
		r.Enabled, r.Source, r.MITRETags,
		r.AutoIsolate, r.AutoKill, r.AutoQuarantine,
		r.Description, r.FalsePositiveRate,
	)
	return err
}

// Delete removes a rule by ID.
func (s *RuleStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM rules WHERE id = $1", id)
	return err
}

// Upsert inserts a rule or updates it if a rule with the same ID already exists.
// Returns (true, nil) if a new row was inserted, (false, nil) if updated.
// Community rules (source='sigmahq') are always updated; custom rules are
// never overwritten by a community sync.
func (s *RuleStore) Upsert(ctx context.Context, r *RuleRow) (created bool, err error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO rules (
			id, name, type, platform, severity, content,
			enabled, source, mitre_tags,
			auto_isolate, auto_kill, auto_quarantine,
			description, false_positive_rate, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			name        = EXCLUDED.name,
			severity    = EXCLUDED.severity,
			content     = EXCLUDED.content,
			mitre_tags  = EXCLUDED.mitre_tags,
			description = EXCLUDED.description,
			updated_at  = NOW()
		WHERE rules.source = 'sigmahq'`,
		r.ID, r.Name, r.Type, r.Platform, r.Severity, r.Content,
		r.Enabled, r.Source, r.MITRETags,
		r.AutoIsolate, r.AutoKill, r.AutoQuarantine,
		r.Description, r.FalsePositiveRate,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Toggle enables or disables a rule. Enabling a quarantined synced rule would
// otherwise violate the quarantined⟹disabled invariant (migration 292), so an
// explicit enable lifts the quarantine to 'enabled' — an operator override. If the
// rule is still noisy the FP monitor re-quarantines it on the next tick.
func (s *RuleStore) Toggle(ctx context.Context, id string, enabled bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE rules
		    SET enabled = $2,
		        curate_state = CASE WHEN $2 AND curate_state = 'quarantined' THEN 'enabled' ELSE curate_state END,
		        updated_at = NOW()
		  WHERE id = $1`,
		id, enabled,
	)
	return err
}

// ─── Notification Store ───────────────────────────────────────

// NotificationStore handles notification channel database operations.
type NotificationStore struct {
	pool *pgxpool.Pool
}

func NewNotificationStore(db *DB) *NotificationStore {
	return &NotificationStore{pool: db.Pool()}
}

type NotifChannelRow struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
	MinSeverity int               `json:"min_severity"`
}

// ListChannels returns all notification channels.
func (s *NotificationStore) ListChannels(ctx context.Context) ([]*NotifChannelRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, config, enabled, min_severity
		FROM notification_channels
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []*NotifChannelRow
	for rows.Next() {
		var ch NotifChannelRow
		var configJSON []byte
		if err := rows.Scan(
			&ch.ID, &ch.Name, &ch.Type, &configJSON, &ch.Enabled, &ch.MinSeverity,
		); err != nil {
			continue
		}
		ch.Config = make(map[string]string)
		if err := json.Unmarshal(configJSON, &ch.Config); err != nil {
			// 設定が読めないチャネルを空の Config のまま返すと、送信先が
			// 空のセンダーが作られ、コンソールでは「有効」に見えたまま
			// アラートごとに送信が失敗します。読めないものは返しません。
			slog.Warn("notification: チャネル設定を解釈できませんでした。このチャネルは無効として扱います",
				"channel", ch.Name, "type", ch.Type, "id", ch.ID, "error", err)
			continue
		}
		channels = append(channels, &ch)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return channels, nil
}

// ─── Command Store ────────────────────────────────────────────

// CommandStore dispatches commands to agents via NATS.
type CommandStore struct {
	pool *pgxpool.Pool
	nc   interface{ Publish(string, []byte) error }
}

func NewCommandStore(db *DB, nc interface{ Publish(string, []byte) error }) *CommandStore {
	return &CommandStore{pool: db.Pool(), nc: nc}
}

// IsolateEndpoint sends an isolation command to an agent and updates the DB.
func (s *CommandStore) IsolateEndpoint(ctx context.Context, agentID, reason, alertID, commandID string) error {
	// Update database
	agentStore := &AgentStore{pool: s.pool}
	if err := agentStore.IsolateAgent(ctx, agentID, reason, "ai_agent"); err != nil {
		return err
	}

	// Publish command via NATS for delivery to the agent
	type isolateCmd struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		Reason    string `json:"reason"`
		AlertID   string `json:"alert_id"`
	}
	data, err := json.Marshal(isolateCmd{AgentID: agentID, CommandID: commandID, Reason: reason, AlertID: alertID})
	if err != nil {
		return fmt.Errorf("marshal isolate command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".isolate", data)
}

// KillProcess sends a process kill command.
func (s *CommandStore) KillProcess(ctx context.Context, agentID string, pid uint32, reason, commandID string) error {
	type killCmd struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		PID       uint32 `json:"pid"`
		Reason    string `json:"reason"`
	}
	data, err := json.Marshal(killCmd{AgentID: agentID, CommandID: commandID, PID: pid, Reason: reason})
	if err != nil {
		return fmt.Errorf("marshal kill command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".kill_process", data)
}

// QuarantineFile sends a file quarantine command.
func (s *CommandStore) QuarantineFile(ctx context.Context, agentID, path, alertID, commandID string) error {
	type quarantineCmd struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		Path      string `json:"path"`
		AlertID   string `json:"alert_id"`
	}
	data, err := json.Marshal(quarantineCmd{AgentID: agentID, CommandID: commandID, Path: path, AlertID: alertID})
	if err != nil {
		return fmt.Errorf("marshal quarantine command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".quarantine_file", data)
}

// RestoreFile sends a file restore command.
func (s *CommandStore) RestoreFile(ctx context.Context, agentID, quarantineID, restorePath, commandID string) error {
	type restoreCmd struct {
		AgentID      string `json:"agent_id"`
		CommandID    string `json:"command_id"`
		QuarantineID string `json:"quarantine_id"`
		RestorePath  string `json:"restore_path"`
	}
	data, err := json.Marshal(restoreCmd{AgentID: agentID, CommandID: commandID, QuarantineID: quarantineID, RestorePath: restorePath})
	if err != nil {
		return fmt.Errorf("marshal restore command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".restore_file", data)
}

// DeleteFile sends a file-delete command — used by rollback to remove an
// incident-created artefact (the inverse of a create). Distinct from quarantine
// (which preserves the file); delete permanently removes it.
func (s *CommandStore) DeleteFile(ctx context.Context, agentID, path, reason, commandID string) error {
	type deleteCmd struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		Path      string `json:"path"`
		Reason    string `json:"reason"`
	}
	data, err := json.Marshal(deleteCmd{AgentID: agentID, CommandID: commandID, Path: path, Reason: reason})
	if err != nil {
		return fmt.Errorf("marshal delete command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".delete_file", data)
}

// UnisolateEndpoint removes network isolation from an agent.
func (s *CommandStore) UnisolateEndpoint(ctx context.Context, agentID, reason, commandID string) error {
	type unisolateCmd struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		Reason    string `json:"reason"`
	}
	data, err := json.Marshal(unisolateCmd{AgentID: agentID, CommandID: commandID, Reason: reason})
	if err != nil {
		return fmt.Errorf("marshal unisolate command: %w", err)
	}
	if err := s.nc.Publish("commands."+agentID+".unisolate", data); err != nil {
		return err
	}
	// Update DB isolation status. Delegate to AgentStore.UnisolateAgent so the
	// correct columns are cleared (status='online', isolated_at/reason/by=NULL);
	// the agents table has no boolean `isolated` column.
	agentStore := &AgentStore{pool: s.pool}
	return agentStore.UnisolateAgent(ctx, agentID)
}

// ApplyPolicyPayload is the payload for an apply_policy command.
type ApplyPolicyPayload struct {
	AgentID         string   `json:"agent_id"`
	PolicyID        string   `json:"policy_id"`
	ScanIntervalMin int      `json:"scan_interval_min"`
	CPULimitPct     int      `json:"cpu_limit_pct"`
	EnabledModules  []string `json:"enabled_modules"`
}

// EnqueueApplyPolicy sends an apply_policy command to an agent via NATS.
func (s *CommandStore) EnqueueApplyPolicy(agentID string, payload ApplyPolicyPayload) error {
	payload.AgentID = agentID
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal apply_policy command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".apply_policy", data)
}

// Scan sends a scan command to an agent.
func (s *CommandStore) Scan(ctx context.Context, agentID, scanType, triggeredBy, commandID string) error {
	type scanCmd struct {
		AgentID     string `json:"agent_id"`
		CommandID   string `json:"command_id"`
		ScanType    string `json:"scan_type"`
		TriggeredBy string `json:"triggered_by"`
	}
	data, err := json.Marshal(scanCmd{AgentID: agentID, CommandID: commandID, ScanType: scanType, TriggeredBy: triggeredBy})
	if err != nil {
		return fmt.Errorf("marshal scan command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".scan", data)
}

// ScanCancel asks the agent to stop the in-flight scan. It reuses the scan
// command with the "__cancel__" target sentinel so no new proto command type
// is needed; the agent cancels its running scan instead of starting one.
func (s *CommandStore) ScanCancel(ctx context.Context, agentID, triggeredBy, commandID string) error {
	type scanCmd struct {
		AgentID     string `json:"agent_id"`
		CommandID   string `json:"command_id"`
		ScanType    string `json:"scan_type"`
		Target      string `json:"target"`
		TriggeredBy string `json:"triggered_by"`
	}
	data, err := json.Marshal(scanCmd{
		AgentID: agentID, ScanType: "full", Target: "__cancel__", TriggeredBy: triggeredBy,
	})
	if err != nil {
		return fmt.Errorf("marshal scan-cancel command: %w", err)
	}
	return s.nc.Publish("commands."+agentID+".scan", data)
}
