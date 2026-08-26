package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EndpointBaseline はフロントエンドに返すベースライン情報。
type EndpointBaseline struct {
	ID                  string          `json:"id"`
	Hostname            string          `json:"hostname"`
	OS                  string          `json:"os"`
	BaselineStatus      string          `json:"baseline_status"`
	LearningStarted     string          `json:"learning_started"`
	DataPointsCollected int64           `json:"data_points_collected"`
	LastUpdated         string          `json:"last_updated"`
	AnomalyCount        int             `json:"anomaly_count"`
	ConfidenceScore     int             `json:"confidence_score"`
	ActiveHours         json.RawMessage `json:"active_hours"`
	TypicalProcesses    json.RawMessage `json:"typical_processes"`
	TypicalDestinations json.RawMessage `json:"typical_destinations"`
	TypicalDirectories  json.RawMessage `json:"typical_directories"`
	RecentDeviations    json.RawMessage `json:"recent_deviations"`
	ExclusionRules      json.RawMessage `json:"exclusion_rules"`
}

// BaselineConfig はグローバルなベースライン設定。
type BaselineConfig struct {
	LearningPeriodDays   int     `json:"learning_period_days"`
	ConfidenceThreshold  float64 `json:"confidence_threshold"`
	AutoAlertOnDeviation bool    `json:"auto_alert_on_deviation"`
	DeviationSensitivity string  `json:"deviation_sensitivity"`
}

// BehavioralBaselineStore は agent_behavioral_baselines テーブルを操作する。
type BehavioralBaselineStore struct {
	pool *pgxpool.Pool
}

// NewBehavioralBaselineStore creates a new BehavioralBaselineStore.
func NewBehavioralBaselineStore(pool *pgxpool.Pool) *BehavioralBaselineStore {
	return &BehavioralBaselineStore{pool: pool}
}

func mapOSType(osType string) string {
	switch osType {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return "Linux"
	}
}

func nullableJSON(b []byte) json.RawMessage {
	if b == nil {
		return json.RawMessage("[]")
	}
	return json.RawMessage(b)
}

// Upsert inserts or updates a baseline row for an agent.
func (s *BehavioralBaselineStore) Upsert(ctx context.Context, b *EndpointBaseline) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	activeHours := []byte(b.ActiveHours)
	if activeHours == nil {
		activeHours = []byte("[]")
	}
	typicalProcesses := []byte(b.TypicalProcesses)
	if typicalProcesses == nil {
		typicalProcesses = []byte("[]")
	}
	typicalDests := []byte(b.TypicalDestinations)
	if typicalDests == nil {
		typicalDests = []byte("[]")
	}
	typicalDirs := []byte(b.TypicalDirectories)
	if typicalDirs == nil {
		typicalDirs = []byte("[]")
	}
	recentDevs := []byte(b.RecentDeviations)
	if recentDevs == nil {
		recentDevs = []byte("[]")
	}
	exclusions := []byte(b.ExclusionRules)
	if exclusions == nil {
		exclusions = []byte("[]")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_behavioral_baselines
			(agent_id, baseline_status, learning_started, data_points_collected,
			 last_updated, anomaly_count, confidence_score,
			 active_hours, typical_processes, typical_destinations,
			 typical_directories, recent_deviations, exclusion_rules)
		VALUES ($1, $2, $3::timestamptz, $4, NOW(), $5, $6,
		        $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb)
		ON CONFLICT (agent_id) DO UPDATE SET
			baseline_status       = EXCLUDED.baseline_status,
			data_points_collected = EXCLUDED.data_points_collected,
			last_updated          = NOW(),
			anomaly_count         = EXCLUDED.anomaly_count,
			confidence_score      = EXCLUDED.confidence_score,
			active_hours          = EXCLUDED.active_hours,
			typical_processes     = EXCLUDED.typical_processes,
			typical_destinations  = EXCLUDED.typical_destinations,
			typical_directories   = EXCLUDED.typical_directories,
			recent_deviations     = EXCLUDED.recent_deviations,
			exclusion_rules       = EXCLUDED.exclusion_rules
	`,
		b.ID,
		b.BaselineStatus,
		b.LearningStarted,
		b.DataPointsCollected,
		b.AnomalyCount,
		b.ConfidenceScore,
		activeHours,
		typicalProcesses,
		typicalDests,
		typicalDirs,
		recentDevs,
		exclusions,
	)
	return err
}

// GetByAgentID returns the baseline for one agent, joined with agents table.
func (s *BehavioralBaselineStore) GetByAgentID(ctx context.Context, agentID string) (*EndpointBaseline, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	row := s.pool.QueryRow(ctx, `
		SELECT b.agent_id, a.hostname, COALESCE(a.os_type,'windows'),
		       b.baseline_status, b.learning_started, b.data_points_collected,
		       b.last_updated, b.anomaly_count, b.confidence_score,
		       b.active_hours, b.typical_processes, b.typical_destinations,
		       b.typical_directories, b.recent_deviations, b.exclusion_rules
		FROM agent_behavioral_baselines b
		JOIN agents a ON a.id = b.agent_id
		WHERE b.agent_id = $1
	`, agentID)

	return scanBaseline(row)
}

// ListAll returns all baselines joined with agents, anomalous first.
func (s *BehavioralBaselineStore) ListAll(ctx context.Context) ([]*EndpointBaseline, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT b.agent_id, a.hostname, COALESCE(a.os_type,'windows'),
		       b.baseline_status, b.learning_started, b.data_points_collected,
		       b.last_updated, b.anomaly_count, b.confidence_score,
		       b.active_hours, b.typical_processes, b.typical_destinations,
		       b.typical_directories, b.recent_deviations, b.exclusion_rules
		FROM agent_behavioral_baselines b
		JOIN agents a ON a.id = b.agent_id
		ORDER BY
		    CASE b.baseline_status
		        WHEN 'anomalous'         THEN 1
		        WHEN 'established'       THEN 2
		        WHEN 'learning'          THEN 3
		        WHEN 'insufficient_data' THEN 4
		        ELSE 5
		    END,
		    b.last_updated DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*EndpointBaseline
	for rows.Next() {
		b, err := scanBaseline(rows)
		if err != nil {
			continue
		}
		results = append(results, b)
	}
	return results, rows.Err()
}

func scanBaseline(row pgx.Row) (*EndpointBaseline, error) {
	var b EndpointBaseline
	var osType string
	var learningStarted, lastUpdated time.Time
	var activeHours, typicalProcesses, typicalDests, typicalDirs, recentDevs, exclusions []byte

	err := row.Scan(
		&b.ID, &b.Hostname, &osType,
		&b.BaselineStatus, &learningStarted, &b.DataPointsCollected,
		&lastUpdated, &b.AnomalyCount, &b.ConfidenceScore,
		&activeHours, &typicalProcesses, &typicalDests,
		&typicalDirs, &recentDevs, &exclusions,
	)
	if err != nil {
		return nil, err
	}

	b.OS = mapOSType(osType)
	b.LearningStarted = learningStarted.Format(time.RFC3339)
	b.LastUpdated = lastUpdated.Format(time.RFC3339)
	b.ActiveHours = nullableJSON(activeHours)
	b.TypicalProcesses = nullableJSON(typicalProcesses)
	b.TypicalDestinations = nullableJSON(typicalDests)
	b.TypicalDirectories = nullableJSON(typicalDirs)
	b.RecentDeviations = nullableJSON(recentDevs)
	b.ExclusionRules = nullableJSON(exclusions)

	return &b, nil
}

// GetConfig reads baseline settings from the settings table.
func (s *BehavioralBaselineStore) GetConfig(ctx context.Context) (*BaselineConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cfg := &BaselineConfig{
		LearningPeriodDays:   30,
		ConfidenceThreshold:  0.85,
		AutoAlertOnDeviation: true,
		DeviationSensitivity: "medium",
	}

	rows, err := s.pool.Query(ctx, `
		SELECT key, value FROM settings
		WHERE key IN (
		    'baseline_learning_period_days',
		    'baseline_confidence_threshold',
		    'baseline_auto_alert',
		    'baseline_deviation_sensitivity'
		)
	`)
	if err != nil {
		// 既定値を返すと、管理者が設定した学習期間や感度が無視された
		// まま逸脱判定が走ります。
		return cfg, fmt.Errorf("ベースライン設定を読めませんでした: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		switch k {
		case "baseline_learning_period_days":
			if n, err := strconv.Atoi(v); err == nil {
				cfg.LearningPeriodDays = n
			}
		case "baseline_confidence_threshold":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.ConfidenceThreshold = f
			}
		case "baseline_auto_alert":
			cfg.AutoAlertOnDeviation = v == "true"
		case "baseline_deviation_sensitivity":
			cfg.DeviationSensitivity = v
		}
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveConfig upserts baseline settings into the settings table.
func (s *BehavioralBaselineStore) SaveConfig(ctx context.Context, cfg *BaselineConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	kv := map[string]string{
		"baseline_learning_period_days":  strconv.Itoa(cfg.LearningPeriodDays),
		"baseline_confidence_threshold":  strconv.FormatFloat(cfg.ConfidenceThreshold, 'f', 2, 64),
		"baseline_auto_alert":            strconv.FormatBool(cfg.AutoAlertOnDeviation),
		"baseline_deviation_sensitivity": cfg.DeviationSensitivity,
	}

	for k, v := range kv {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO settings (key, value)
			VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
		`, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetExclusionRules fetches current exclusion_rules for one agent.
//
// 以前の条件は `errors.Is(err, pgx.ErrNoRows) || err != nil` —— つまり
// 「行が無い」も「読めなかった」も同じ [] を返していました。呼び出し側
// （baseline_rebuilder）はこれを「既存の除外ルール」として持ち回り、
// そのままベースラインを Upsert します。読めなかっただけで、運用担当が
// 設定した除外ルールが消えます。
func (s *BehavioralBaselineStore) GetExclusionRules(ctx context.Context, agentID string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT exclusion_rules FROM agent_behavioral_baselines WHERE agent_id = $1`,
		agentID,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return json.RawMessage("[]"), nil // まだベースラインが無い
	}
	if err != nil {
		return nil, fmt.Errorf("除外ルールを読めませんでした: %w", err)
	}
	return json.RawMessage(raw), nil
}
