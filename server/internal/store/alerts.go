package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// AlertStore handles all alert-related database operations.
type AlertStore struct {
	pool      *pgxpool.Pool
	encryptor *tenantcrypto.Encryptor
	// publisher is an optional NATS connection used to emit investigation
	// trigger messages when a high-severity alert is saved.
	publisher *nats.Conn
}

// WithPublisher attaches a NATS connection to the AlertStore so that
// SaveAlert can publish investigation trigger messages for high-severity
// alerts.  Calling this with nil is a no-op.
func (s *AlertStore) WithPublisher(nc *nats.Conn) *AlertStore {
	s.publisher = nc
	return s
}

func NewAlertStore(db *DB) *AlertStore {
	return &AlertStore{pool: db.Pool()}
}

// Pool exposes the underlying connection pool for operations not covered by AlertStore methods.
func (s *AlertStore) Pool() *pgxpool.Pool { return s.pool }

// WithEncryptor attaches a tenant Encryptor to the AlertStore, enabling
// AES-256-GCM encryption of raw_event data at rest.  Calling this with a nil
// encryptor is a no-op (encryption remains disabled).
func (s *AlertStore) WithEncryptor(enc *tenantcrypto.Encryptor) *AlertStore {
	s.encryptor = enc
	return s
}

// StoredAlert mirrors the alerts table.
type StoredAlert struct {
	ID             string     `json:"id"`
	RuleID         *string    `json:"rule_id,omitempty"`
	RuleName       *string    `json:"rule_name,omitempty"`
	AgentID        string     `json:"agent_id"`
	Hostname       string     `json:"agent_hostname"`
	OS             string     `json:"agent_os"`
	Severity       int        `json:"severity"`
	Status         string     `json:"status"`
	Title          string     `json:"title"`
	Description    *string    `json:"description,omitempty"`
	EventIDs       []string   `json:"event_ids,omitempty"`
	MITRETech      *string    `json:"mitre_technique,omitempty"`
	AnomalyScore   *float64   `json:"anomaly_score,omitempty"`
	AIAnalyzed     bool       `json:"ai_analyzed"`
	AIIsThreat     *bool      `json:"ai_is_threat,omitempty"`
	AISeverity     *int       `json:"ai_severity,omitempty"`
	AIConfidence   *float64   `json:"ai_confidence,omitempty"`
	AIThreatName   *string    `json:"ai_threat_name,omitempty"`
	AISummary      *string    `json:"ai_summary,omitempty"`
	AIReport       *string    `json:"ai_report,omitempty"`
	AIAttackChain  []string   `json:"ai_attack_chain,omitempty"`
	AIMITRETags    []string   `json:"ai_mitre_tags,omitempty"`
	AssignedTo     *string    `json:"assigned_to,omitempty"`
	AssignedToName *string    `json:"assigned_to_name,omitempty"`
	CommentCount   int        `json:"comment_count"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	// RawEvent holds the original triggering event payload.  When encryption is
	// enabled on the AlertStore the value stored in the database is an
	// AES-256-GCM ciphertext encoded as "enc:<base64>".  Callers receive the
	// decrypted JSON in this field after a successful read (decryption is not
	// yet wired into read paths — raw storage only for now).
	RawEvent json.RawMessage `json:"raw_event,omitempty"`
	// TenantID is used as the encryption scope key.  It is not persisted as its
	// own column but is required when encryption is active.
	TenantID string `json:"-"`
}

// encryptedRawEventPrefix is prepended to the base64-encoded ciphertext so
// readers can distinguish encrypted values from plain-text JSON.
const encryptedRawEventPrefix = "enc:"

// prepareRawEvent returns the value to be stored in the raw_event column.
// When an encryptor and a tenantID are available the JSON payload is encrypted
// with AES-256-GCM and returned as "enc:<base64>".  Otherwise the raw JSON is
// returned unchanged.  A nil or empty RawEvent results in a nil return value
// (the column will be left NULL).
func (s *AlertStore) prepareRawEvent(ctx context.Context, a *StoredAlert) (*string, error) {
	if len(a.RawEvent) == 0 {
		return nil, nil
	}

	if s.encryptor == nil || a.TenantID == "" {
		// No encryption configured — store as plain JSON string.
		plain := string(a.RawEvent)
		return &plain, nil
	}

	ciphertext, err := s.encryptor.Encrypt(ctx, a.TenantID, []byte(a.RawEvent))
	if err != nil {
		return nil, fmt.Errorf("alertstore: encrypt raw_event for alert %s: %w", a.ID, err)
	}

	encoded := encryptedRawEventPrefix + base64.StdEncoding.EncodeToString(ciphertext)
	return &encoded, nil
}

// SaveAlert inserts a new alert.  If the AlertStore has an Encryptor configured
// and the alert carries a non-empty TenantID, the raw_event field is encrypted
// with AES-256-GCM before being written to the database.
func (s *AlertStore) SaveAlert(ctx context.Context, a *StoredAlert) error {
	rawEventVal, err := s.prepareRawEvent(ctx, a)
	if err != nil {
		// Log the error but do not block the alert from being saved.
		slog.Warn("raw_event encryption failed; storing without raw_event",
			"alert_id", a.ID, "error", err)
		rawEventVal = nil
	}

	// agent_id is a uuid column. Agentless alerts — e.g. the cloud
	// suspicious-operation path, which keys off a cloud account, not an endpoint —
	// carry no agent, so AgentID is "". Binding "" to a uuid fails with SQLSTATE
	// 22P02 ("invalid input syntax for type uuid"), which silently drops the alert.
	// Bind NULL instead when there is no agent. (rule_id is already a *string that
	// the caller leaves nil for the same reason.)
	var agentIDArg any
	if a.AgentID != "" {
		agentIDArg = a.AgentID
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO alerts (
			id, rule_id, agent_id, severity, status, title, description,
			mitre_technique, anomaly_score, raw_event, created_at, updated_at,
			ai_mitre_tags, event_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::uuid[])`,
		a.ID, a.RuleID, agentIDArg, a.Severity, a.Status, a.Title,
		a.Description, a.MITRETech, a.AnomalyScore, rawEventVal,
		a.CreatedAt, a.UpdatedAt, a.AIMITRETags, a.EventIDs,
	)
	if err != nil {
		return err
	}

	// Publish an AI investigation trigger for alerts that meet the configured
	// severity threshold.  The threshold is read from system_settings
	// (`ai_auto_investigate_threshold`) and defaults to 7 if unavailable.
	// Failures are non-fatal and only logged.
	if s.publisher != nil && a.Severity >= s.autoInvestigateThreshold(ctx) {
		if pubErr := s.publisher.Publish("edr.investigation.trigger", []byte(a.ID)); pubErr != nil {
			slog.Warn("alertstore: failed to publish investigation trigger",
				"alert_id", a.ID, "error", pubErr)
		}
	}
	return nil
}

// autoInvestigateThreshold reads the AI auto-investigation severity threshold
// from system_settings.  Falls back to 7 when the setting is missing or invalid.
func (s *AlertStore) autoInvestigateThreshold(ctx context.Context) int {
	const fallback = 7
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'ai_auto_investigate_threshold'`).
		Scan(&raw)
	if err != nil {
		return fallback
	}
	var v int
	if jsonErr := json.Unmarshal(raw, &v); jsonErr == nil && v >= 1 && v <= 10 {
		return v
	}
	return fallback
}

// GetAlert retrieves a single alert with agent info.
func (s *AlertStore) GetAlert(ctx context.Context, id string) (*StoredAlert, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			al.id, al.rule_id, r.name, al.agent_id, ag.hostname, ag.os_type,
			al.severity, al.status, al.title, al.description,
			al.mitre_technique, al.anomaly_score,
			al.ai_analyzed, al.ai_is_threat, al.ai_severity,
			al.ai_confidence, al.ai_threat_name, al.ai_summary,
			al.ai_report, al.ai_attack_chain, al.ai_mitre_tags,
			al.assigned_to, u.full_name, al.resolved_at, al.created_at, al.updated_at
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		LEFT JOIN users u ON u.id = al.assigned_to::uuid
		WHERE al.id = $1`, id)

	a, err := scanAlert(row)
	if err != nil {
		return nil, err
	}

	// Fetch raw_event separately (decryption not yet wired in).
	var rawEventStr *string
	_ = s.pool.QueryRow(ctx, `SELECT raw_event FROM alerts WHERE id = $1`, id).Scan(&rawEventStr)
	if rawEventStr != nil && !strings.HasPrefix(*rawEventStr, encryptedRawEventPrefix) {
		a.RawEvent = json.RawMessage(*rawEventStr)
	}
	return a, nil
}

// UpdateAlert updates mutable alert fields.
func (s *AlertStore) UpdateAlert(ctx context.Context, id string, status *string, analysis *AIAnalysisUpdate, assignedTo ...*string) error {
	// Capture previous status BEFORE the update so history tracking is accurate.
	var prevStatus string
	if status != nil {
		_ = s.pool.QueryRow(ctx, "SELECT status FROM alerts WHERE id = $1", id).Scan(&prevStatus)
	}

	sets := []string{"updated_at = NOW()"}
	args := []interface{}{id}
	i := 2

	if status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", i))
		args = append(args, *status)
		i++
	}

	if len(assignedTo) > 0 && assignedTo[0] != nil {
		if *assignedTo[0] == "" {
			// 空文字 = 割り当て解除 → NULL
			sets = append(sets, "assigned_to = NULL")
		} else {
			sets = append(sets, fmt.Sprintf("assigned_to = $%d", i))
			args = append(args, *assignedTo[0])
			i++
		}
	}

	if analysis != nil {
		sets = append(sets,
			"ai_analyzed = true",
			fmt.Sprintf("ai_is_threat = $%d", i),
			fmt.Sprintf("ai_severity = $%d", i+1),
			fmt.Sprintf("ai_confidence = $%d", i+2),
			fmt.Sprintf("ai_threat_name = $%d", i+3),
			fmt.Sprintf("ai_summary = $%d", i+4),
			fmt.Sprintf("ai_report = $%d", i+5),
			fmt.Sprintf("ai_attack_chain = $%d", i+6),
			fmt.Sprintf("ai_mitre_tags = $%d", i+7),
		)
		args = append(args,
			analysis.IsThreat, analysis.Severity, analysis.Confidence,
			analysis.ThreatName, analysis.Summary, analysis.Report,
			analysis.AttackChain, analysis.MITRETags,
		)
		i += 8
	}

	query := fmt.Sprintf(
		"UPDATE alerts SET %s WHERE id = $1",
		strings.Join(sets, ", "),
	)

	_, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}

	// Record status change for MTTD/MTTR tracking.
	if status != nil && prevStatus != *status {
		changedBy := "system"
		if len(assignedTo) > 0 && assignedTo[0] != nil {
			changedBy = *assignedTo[0]
		}
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO alert_status_changes (alert_id, from_status, to_status, changed_by)
			VALUES ($1::uuid, $2, $3, $4)`,
			id, prevStatus, *status, changedBy,
		)
	}
	return nil
}

// AIAnalysisUpdate contains the AI analysis fields to persist.
type AIAnalysisUpdate struct {
	IsThreat    bool
	Severity    int
	Confidence  float64
	ThreatName  string
	Summary     string
	Report      string
	AttackChain []string
	MITRETags   []string
}

// ListAlerts returns alerts with pagination and filtering.
func (s *AlertStore) ListAlerts(ctx context.Context, filter AlertFilter) ([]*StoredAlert, int, error) {
	where, args := buildAlertWhere(filter)
	countQuery := "SELECT COUNT(*) FROM alerts al " + where
	listQuery := `
		SELECT
			al.id, al.rule_id, r.name, al.agent_id, ag.hostname, ag.os_type,
			al.severity, al.status, al.title, al.description,
			al.mitre_technique, al.anomaly_score,
			al.ai_analyzed, al.ai_is_threat, al.ai_severity,
			al.ai_confidence, al.ai_threat_name, al.ai_summary,
			al.ai_report, al.ai_attack_chain, al.ai_mitre_tags,
			al.assigned_to, u.full_name,
			(SELECT COUNT(*) FROM alert_comments ac WHERE ac.alert_id = al.id) AS comment_count,
			al.resolved_at, al.created_at, al.updated_at
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		LEFT JOIN users u ON u.id = al.assigned_to::uuid
		` + where + `
		ORDER BY al.created_at DESC
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) +
		` OFFSET $` + fmt.Sprintf("%d", len(args)+2)

	var total int
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, filter.Limit, filter.Offset)
	rows, err := s.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []*StoredAlert
	for rows.Next() {
		var a StoredAlert
		var aiAttackChain []byte
		// ai_mitre_tags is a native TEXT[] column — scan straight into []string.
		// (It was previously scanned as []byte + json.Unmarshal, which silently
		// failed once the column held a value, dropping the whole alert row.)
		err := rows.Scan(
			&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.Hostname, &a.OS,
			&a.Severity, &a.Status, &a.Title, &a.Description,
			&a.MITRETech, &a.AnomalyScore,
			&a.AIAnalyzed, &a.AIIsThreat, &a.AISeverity,
			&a.AIConfidence, &a.AIThreatName, &a.AISummary,
			&a.AIReport, &aiAttackChain, &a.AIMITRETags,
			&a.AssignedTo, &a.AssignedToName, &a.CommentCount,
			&a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			continue
		}
		if aiAttackChain != nil {
			if err := json.Unmarshal(aiAttackChain, &a.AIAttackChain); err != nil {
				slog.Warn("ai_attack_chain JSONの解析に失敗しました", "alert_id", a.ID, "error", err)
			}
		}
		alerts = append(alerts, &a)
	}

	return alerts, total, nil
}

// AlertStats returns aggregated alert statistics for the dashboard.
func (s *AlertStore) AlertStats(ctx context.Context) (*AlertStatSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'open')          AS open_count,
			COUNT(*) FILTER (WHERE status = 'investigating') AS investigating_count,
			COUNT(*) FILTER (WHERE status = 'resolved')      AS resolved_count,
			COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
			COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS today_count,
			severity,
			COUNT(*) AS sev_count
		FROM alerts
		GROUP BY ROLLUP(severity)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &AlertStatSummary{
		BySeverity: make(map[int]int),
	}

	for rows.Next() {
		var open, investigating, resolved, fp, today int
		var sev *int
		var sevCount int
		if err := rows.Scan(&open, &investigating, &resolved, &fp, &today, &sev, &sevCount); err != nil {
			continue
		}
		if sev == nil {
			stats.Open = open
			stats.Investigating = investigating
			stats.Resolved = resolved
			stats.FalsePositive = fp
			stats.TodayCount = today
			stats.Total = open + investigating + resolved + fp
		} else {
			stats.BySeverity[*sev] = sevCount
		}
	}

	return stats, nil
}

// AlertStatSummary aggregates alert counts.
type AlertStatSummary struct {
	Total         int         `json:"total"`
	Open          int         `json:"open"`
	Investigating int         `json:"investigating"`
	Resolved      int         `json:"resolved"`
	FalsePositive int         `json:"false_positive"`
	TodayCount    int         `json:"today_count"`
	BySeverity    map[int]int `json:"by_severity"`
}

// AlertFilter defines list query filters.
type AlertFilter struct {
	Status         string
	AgentID        string
	RuleID         string
	Severity       int
	SeverityMax    int
	Search         string
	MITRETech      string
	FromTime       *time.Time
	ToTime         *time.Time
	AIInvestigated bool // true → only alerts with a persisted ai_summary
	Limit          int
	Offset         int
}

// TopAgent holds per-agent alert aggregation for the dashboard.
type TopAgent struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	AlertCount  int    `json:"alert_count"`
	MaxSeverity int    `json:"max_severity"`
}

// TopThreatenedAgents returns the top N agents by alert count over the past 7 days.
func (s *AlertStore) TopThreatenedAgents(ctx context.Context, limit int) ([]TopAgent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT al.agent_id::text,
		       COALESCE(ag.hostname, al.agent_id::text) AS hostname,
		       COUNT(*)                            AS alert_count,
		       MAX(al.severity)                    AS max_severity
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		WHERE al.created_at >= NOW() - INTERVAL '7 days'
		GROUP BY al.agent_id, ag.hostname
		ORDER BY alert_count DESC, max_severity DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []TopAgent
	for rows.Next() {
		var a TopAgent
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.AlertCount, &a.MaxSeverity); err != nil {
			continue
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// RelatedAlert is a lightweight alert summary for correlation views.
type RelatedAlert struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  int       `json:"severity"`
	Status    string    `json:"status"`
	Hostname  string    `json:"hostname"`
	RuleName  string    `json:"rule_name"`
	MITRETech string    `json:"mitre_technique"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"` // why it's related: "same_host" | "same_rule" | "same_mitre"
}

// GetRelated returns alerts correlated with the given alert by shared host, rule, or MITRE technique
// within the past 7 days, excluding the alert itself.
func (s *AlertStore) GetRelated(ctx context.Context, alertID string, limit int) ([]*RelatedAlert, error) {
	rows, err := s.pool.Query(ctx, `
		WITH base AS (
			SELECT agent_id, rule_id, mitre_technique
			FROM alerts WHERE id = $1
		)
		SELECT DISTINCT al.id,
			al.title,
			al.severity,
			al.status,
			COALESCE(ag.hostname, al.agent_id::text) AS hostname,
			COALESCE(r.name, '') AS rule_name,
			COALESCE(al.mitre_technique, '') AS mitre_technique,
			al.created_at,
			CASE
				WHEN al.agent_id    = base.agent_id        THEN 'same_host'
				WHEN al.rule_id     = base.rule_id         THEN 'same_rule'
				WHEN al.mitre_technique IS NOT NULL
				  AND al.mitre_technique = base.mitre_technique THEN 'same_mitre'
				ELSE 'related'
			END AS reason
		FROM alerts al
		CROSS JOIN base
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules  r  ON r.id  = al.rule_id
		WHERE al.id != $1
		  AND al.created_at >= NOW() - INTERVAL '7 days'
		  AND al.status != 'false_positive'
		  AND (
			al.agent_id = base.agent_id
			OR (base.rule_id IS NOT NULL AND al.rule_id = base.rule_id)
			OR (base.mitre_technique IS NOT NULL AND al.mitre_technique = base.mitre_technique)
		  )
		ORDER BY al.created_at DESC
		LIMIT $2`,
		alertID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var related []*RelatedAlert
	for rows.Next() {
		r := &RelatedAlert{}
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Status, &r.Hostname, &r.RuleName, &r.MITRETech, &r.CreatedAt, &r.Reason); err != nil {
			continue
		}
		related = append(related, r)
	}
	if related == nil {
		related = []*RelatedAlert{}
	}
	return related, nil
}

// AlertCountInWindow returns number of alerts created in [NOW-fromHours, NOW-toHours].
func (s *AlertStore) AlertCountInWindow(ctx context.Context, fromHours, toHours int) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE created_at >= NOW() - $1::interval
		  AND created_at <  NOW() - $2::interval`,
		fmt.Sprintf("%d hours", fromHours),
		fmt.Sprintf("%d hours", toHours),
	).Scan(&count)
	return count, err
}

// AlertTimelineBucket represents hourly alert counts.
type AlertTimelineBucket struct {
	Bucket time.Time
	Count  int
}

// AlertTimeline returns hourly alert counts for the past N hours.
func (s *AlertStore) AlertTimeline(ctx context.Context, hours int) ([]AlertTimelineBucket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('hour', created_at) AS bucket, COUNT(*) AS cnt
		FROM alerts
		WHERE created_at >= NOW() - $1::interval
		GROUP BY bucket
		ORDER BY bucket ASC`,
		fmt.Sprintf("%d hours", hours),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []AlertTimelineBucket
	for rows.Next() {
		var b AlertTimelineBucket
		if err := rows.Scan(&b.Bucket, &b.Count); err != nil {
			continue
		}
		buckets = append(buckets, b)
	}
	return buckets, nil
}

// GetAlertHistory returns recent alert summaries for an agent (used by AI context).
func (s *AlertStore) GetAlertHistory(ctx context.Context, agentID string, days int) ([]AlertSummaryRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT title, severity, created_at, status
		FROM alerts
		WHERE agent_id = $1 AND created_at >= NOW() - $2::interval
		ORDER BY created_at DESC
		LIMIT 20`,
		agentID, fmt.Sprintf("%d days", days),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AlertSummaryRow
	for rows.Next() {
		var r AlertSummaryRow
		if err := rows.Scan(&r.Title, &r.Severity, &r.CreatedAt, &r.Status); err != nil {
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

type AlertSummaryRow struct {
	Title     string
	Severity  int
	CreatedAt time.Time
	Status    string
}

// SaveResponseAction logs a response action.
func (s *AlertStore) SaveResponseAction(ctx context.Context, action *ResponseActionRow) error {
	// success は status_text から導出される生成列なので直接書けない
	// (migration 379)。呼び出し側の bool を語彙に写す。
	status := StatusSuccess
	if !action.Success {
		status = StatusFailure
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO response_actions (
			id, alert_id, agent_id, action_type, target,
			reason, executed_by, status_text, error_msg, executed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		action.ID, action.AlertID, action.AgentID, action.ActionType,
		action.Target, action.Reason, action.ExecutedBy,
		status, action.ErrorMsg, action.ExecutedAt,
	)
	return err
}

type ResponseActionRow struct {
	ID         string
	AlertID    *string
	AgentID    string
	ActionType string
	Target     *string
	Reason     *string
	ExecutedBy string
	Success    bool
	ErrorMsg   *string
	ExecutedAt time.Time
}

// AddComment persists a comment on an alert.
func (s *AlertStore) AddComment(ctx context.Context, alertID, userID, content string) (string, time.Time, error) {
	var id string
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_comments (alert_id, user_id, content)
		VALUES ($1, $2::uuid, $3)
		RETURNING id, created_at`,
		alertID, userID, content,
	).Scan(&id, &createdAt)
	return id, createdAt, err
}

// ListComments retrieves comments for an alert ordered by creation time.
func (s *AlertStore) ListComments(ctx context.Context, alertID string) ([]AlertComment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ac.id, ac.alert_id, COALESCE(ac.user_id::text, ''),
		       COALESCE(u.full_name, ac.user_id::text, 'Unknown'), ac.content, ac.created_at
		FROM alert_comments ac
		LEFT JOIN users u ON u.id = ac.user_id
		WHERE ac.alert_id = $1
		ORDER BY ac.created_at ASC`,
		alertID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []AlertComment
	for rows.Next() {
		var cm AlertComment
		if err := rows.Scan(&cm.ID, &cm.AlertID, &cm.UserID, &cm.UserName, &cm.Content, &cm.CreatedAt); err != nil {
			continue
		}
		comments = append(comments, cm)
	}
	return comments, nil
}

type AlertComment struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"`
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── Helpers ──────────────────────────────────────────────────

func scanAlert(row pgx.Row) (*StoredAlert, error) {
	var a StoredAlert
	var aiAttackChain []byte // ai_mitre_tags is TEXT[] — scan straight into []string

	err := row.Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.AgentID, &a.Hostname, &a.OS,
		&a.Severity, &a.Status, &a.Title, &a.Description,
		&a.MITRETech, &a.AnomalyScore,
		&a.AIAnalyzed, &a.AIIsThreat, &a.AISeverity,
		&a.AIConfidence, &a.AIThreatName, &a.AISummary,
		&a.AIReport, &aiAttackChain, &a.AIMITRETags,
		&a.AssignedTo, &a.AssignedToName, &a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if aiAttackChain != nil {
		if err := json.Unmarshal(aiAttackChain, &a.AIAttackChain); err != nil {
			slog.Warn("ai_attack_chain JSONの解析に失敗しました", "alert_id", a.ID, "error", err)
		}
	}

	return &a, nil
}

func buildAlertWhere(f AlertFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	i := 1

	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("al.status = $%d", i))
		args = append(args, f.Status)
		i++
	}
	if f.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("al.agent_id = $%d", i))
		args = append(args, f.AgentID)
		i++
	}
	if f.RuleID != "" {
		conditions = append(conditions, fmt.Sprintf("al.rule_id = $%d", i))
		args = append(args, f.RuleID)
		i++
	}
	if f.Severity > 0 {
		conditions = append(conditions, fmt.Sprintf("al.severity >= $%d", i))
		args = append(args, f.Severity)
		i++
	}
	if f.SeverityMax > 0 {
		conditions = append(conditions, fmt.Sprintf("al.severity <= $%d", i))
		args = append(args, f.SeverityMax)
		i++
	}
	if f.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(al.title ILIKE $%d OR al.description ILIKE $%d OR EXISTS (SELECT 1 FROM agents _ag WHERE _ag.id = al.agent_id AND _ag.hostname ILIKE $%d))", i, i, i,
		))
		args = append(args, "%"+f.Search+"%")
		i++
	}
	if f.MITRETech != "" {
		// Match rule-based technique OR any AI-mapped technique in the array
		conditions = append(conditions, fmt.Sprintf(
			"(al.mitre_technique ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(COALESCE(al.ai_mitre_tags, '{}')) _t WHERE _t ILIKE $%d))",
			i, i,
		))
		args = append(args, f.MITRETech+"%")
		i++
	}
	if f.FromTime != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at >= $%d", i))
		args = append(args, *f.FromTime)
		i++
	}
	if f.ToTime != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at <= $%d", i))
		args = append(args, *f.ToTime)
		i++
	}
	if f.AIInvestigated {
		// Only alerts that have a persisted AI investigation summary.
		conditions = append(conditions, "al.ai_summary IS NOT NULL AND al.ai_summary <> ''")
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}
