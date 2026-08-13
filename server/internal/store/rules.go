package store

import (
	"context"
	"encoding/json"
	"fmt"
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
	return rules, nil
}

// List returns rules with optional filtering and pagination.
func (s *RuleStore) List(ctx context.Context, filter RuleFilter) ([]*RuleRow, int, error) {
	var conditions []string
	var args []interface{}
	i := 1

	if filter.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", i))
		args = append(args, filter.Type)
		i++
	}
	if filter.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", i))
		args = append(args, *filter.Enabled)
		i++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", i, i))
		args = append(args, "%"+filter.Search+"%")
		i++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

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

// Create inserts a new rule.
func (s *RuleStore) Create(ctx context.Context, r *RuleRow) error {
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
		_ = json.Unmarshal(configJSON, &ch.Config)
		channels = append(channels, &ch)
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
