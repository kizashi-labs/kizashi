// Package backup provides JSON-based configuration backup and restore for the EDR platform.
// It exports core config tables to a single JSON blob and can restore them via upsert.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const platformVersion = "1.0"

// allowedRestoreTables is the whitelist of tables that may be targeted by a
// restore operation. Table names in upsertJSON are validated against this set
// to prevent arbitrary table writes if backup data is tampered with.
var allowedRestoreTables = map[string]bool{
	"detection_rules":   true,
	"sso_configs":       true,
	"siem_configs":      true,
	"webhooks":          true,
	"suppression_rules": true,
	"yara_rules":        true,
	"agent_profiles":    true,
}

// BackupManifest describes metadata for a single backup.
type BackupManifest struct {
	ID          string         `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	Version     string         `json:"version"`
	Tables      []string       `json:"tables"`
	RecordCount map[string]int `json:"record_count"`
	SizeBytes   int64          `json:"size_bytes"`
	Status      string         `json:"status"` // completed/failed
	FilePath    string         `json:"file_path"`
}

// BackupData is the full backup payload.
type BackupData struct {
	Manifest      BackupManifest   `json:"manifest"`
	Rules         []map[string]any `json:"rules"` // detection_rules
	SSOCfg        []map[string]any `json:"sso_configs"`
	SIEMCfg       []map[string]any `json:"siem_configs"`
	Webhooks      []map[string]any `json:"webhooks"`
	Suppression   []map[string]any `json:"suppression_rules"`
	YARARules     []map[string]any `json:"yara_rules"`
	AgentProfiles []map[string]any `json:"agent_profiles"`
}

// RestoreResult summarises a restore operation.
type RestoreResult struct {
	TablesRestored  []string       `json:"tables_restored"`
	RecordsRestored map[string]int `json:"records_restored"`
	Warnings        []string       `json:"warnings"`
}

// Manager handles backup/restore operations.
type Manager struct {
	pool      *pgxpool.Pool
	backupDir string
}

// NewManager creates a new Manager. backupDir defaults to "./backups".
func NewManager(pool *pgxpool.Pool, backupDir string) *Manager {
	if backupDir == "" {
		if _, err := os.Stat("/var/edr/backups"); err == nil {
			backupDir = "/var/edr/backups"
		} else {
			backupDir = "./backups"
		}
	}
	return &Manager{pool: pool, backupDir: backupDir}
}

// CreateBackup dumps configuration tables to a BackupData JSON blob.
// It also persists a manifest record to the DB and returns the raw JSON bytes.
func (m *Manager) CreateBackup(ctx context.Context) (*BackupManifest, []byte, error) {
	bd := &BackupData{}
	bd.Manifest = BackupManifest{
		CreatedAt:   time.Now().UTC(),
		Version:     platformVersion,
		RecordCount: make(map[string]int),
	}

	// Export each table
	type tableExport struct {
		name   string
		query  string
		target *[]map[string]any
	}
	exports := []tableExport{
		{
			name:   "detection_rules",
			query:  "SELECT id, name, description, query, severity, enabled, created_at, updated_at FROM detection_rules ORDER BY created_at",
			target: &bd.Rules,
		},
		{
			name:   "sso_configs",
			query:  "SELECT id, provider, client_id, client_secret, metadata_url, enabled, created_at FROM sso_configs ORDER BY created_at",
			target: &bd.SSOCfg,
		},
		{
			name:   "siem_targets",
			query:  "SELECT id, name, type, host, port, protocol, token, tls_enabled, index_name, enabled, min_severity, created_at FROM siem_targets ORDER BY created_at",
			target: &bd.SIEMCfg,
		},
		{
			name:   "webhook_targets",
			query:  "SELECT id, name, url, events, enabled, created_at FROM webhook_targets ORDER BY created_at",
			target: &bd.Webhooks,
		},
		{
			name:   "suppression_rules",
			query:  "SELECT id, name, conditions, enabled, created_at FROM suppression_rules ORDER BY created_at",
			target: &bd.Suppression,
		},
		{
			name:   "yara_rules",
			query:  "SELECT id, name, rule_content, enabled, created_at FROM yara_rules ORDER BY created_at",
			target: &bd.YARARules,
		},
		{
			name:   "agent_profiles",
			query:  "SELECT id, name, settings, created_at FROM agent_profiles ORDER BY created_at",
			target: &bd.AgentProfiles,
		},
	}

	for _, exp := range exports {
		rows, err := m.pool.Query(ctx, exp.query)
		if err != nil {
			slog.Warn("backup: skipping table due to query error",
				"table", exp.name, "error", err)
			bd.Manifest.RecordCount[exp.name] = 0
			continue
		}

		var records []map[string]any
		fields := rows.FieldDescriptions()
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				continue
			}
			row := make(map[string]any, len(fields))
			for i, f := range fields {
				row[string(f.Name)] = vals[i]
			}
			records = append(records, row)
		}
		rows.Close()

		if records == nil {
			records = []map[string]any{}
		}
		*exp.target = records
		bd.Manifest.RecordCount[exp.name] = len(records)
		bd.Manifest.Tables = append(bd.Manifest.Tables, exp.name)
	}

	bd.Manifest.Status = "completed"

	raw, err := json.MarshalIndent(bd, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal backup: %w", err)
	}
	bd.Manifest.SizeBytes = int64(len(raw))

	// Persist manifest to DB
	if m.pool != nil {
		rcJSON, _ := json.Marshal(bd.Manifest.RecordCount)
		var id string
		dbErr := m.pool.QueryRow(ctx, `
			INSERT INTO backup_manifests (version, tables, record_count, size_bytes, status)
			VALUES ($1, $2, $3::jsonb, $4, 'completed')
			RETURNING id`,
			bd.Manifest.Version,
			bd.Manifest.Tables,
			string(rcJSON),
			bd.Manifest.SizeBytes,
		).Scan(&id)
		if dbErr == nil {
			bd.Manifest.ID = id
		} else {
			slog.Warn("backup: failed to persist manifest", "error", dbErr)
			bd.Manifest.ID = fmt.Sprintf("local-%d", time.Now().UnixNano())
		}
	} else {
		bd.Manifest.ID = fmt.Sprintf("local-%d", time.Now().UnixNano())
	}

	// Re-marshal with the ID set
	raw, _ = json.MarshalIndent(bd, "", "  ")
	bd.Manifest.SizeBytes = int64(len(raw))

	return &bd.Manifest, raw, nil
}

// RestoreBackup parses a backup JSON blob and upserts config records.
// Gracefully skips tables that are missing or have errors.
func (m *Manager) RestoreBackup(ctx context.Context, data []byte) (*RestoreResult, error) {
	var bd BackupData
	if err := json.Unmarshal(data, &bd); err != nil {
		return nil, fmt.Errorf("invalid backup format: %w", err)
	}

	result := &RestoreResult{
		RecordsRestored: make(map[string]int),
	}

	// Restore detection_rules
	if len(bd.Rules) > 0 {
		n, warn := m.upsertJSON(ctx, "detection_rules", bd.Rules, "id")
		result.RecordsRestored["detection_rules"] = n
		result.TablesRestored = append(result.TablesRestored, "detection_rules")
		if warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
	}

	// Restore webhook_targets
	if len(bd.Webhooks) > 0 {
		n, warn := m.upsertJSON(ctx, "webhook_targets", bd.Webhooks, "id")
		result.RecordsRestored["webhook_targets"] = n
		result.TablesRestored = append(result.TablesRestored, "webhook_targets")
		if warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
	}

	// Restore siem_targets
	if len(bd.SIEMCfg) > 0 {
		n, warn := m.upsertJSON(ctx, "siem_targets", bd.SIEMCfg, "id")
		result.RecordsRestored["siem_targets"] = n
		result.TablesRestored = append(result.TablesRestored, "siem_targets")
		if warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
	}

	// Restore yara_rules
	if len(bd.YARARules) > 0 {
		n, warn := m.upsertJSON(ctx, "yara_rules", bd.YARARules, "id")
		result.RecordsRestored["yara_rules"] = n
		result.TablesRestored = append(result.TablesRestored, "yara_rules")
		if warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
	}

	// Restore suppression_rules
	if len(bd.Suppression) > 0 {
		n, warn := m.upsertJSON(ctx, "suppression_rules", bd.Suppression, "id")
		result.RecordsRestored["suppression_rules"] = n
		result.TablesRestored = append(result.TablesRestored, "suppression_rules")
		if warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
	}

	slog.Info("backup restore completed",
		"tables", len(result.TablesRestored),
		"warnings", len(result.Warnings),
	)
	return result, nil
}

// ListBackups returns backup manifests from the DB ordered by created_at desc.
func (m *Manager) ListBackups(ctx context.Context) ([]*BackupManifest, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT id, created_at, COALESCE(version,''), COALESCE(tables,'{}'),
		       COALESCE(record_count,'{}')::text, COALESCE(size_bytes,0),
		       COALESCE(status,'completed'), COALESCE(file_path,'')
		FROM backup_manifests
		ORDER BY created_at DESC
		LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}
	defer rows.Close()

	var manifests []*BackupManifest
	for rows.Next() {
		var m BackupManifest
		var rcJSON string
		if err := rows.Scan(
			&m.ID, &m.CreatedAt, &m.Version, &m.Tables,
			&rcJSON, &m.SizeBytes, &m.Status, &m.FilePath,
		); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(rcJSON), &m.RecordCount)
		if m.RecordCount == nil {
			m.RecordCount = make(map[string]int)
		}
		manifests = append(manifests, &m)
	}
	if manifests == nil {
		manifests = []*BackupManifest{}
	}
	return manifests, nil
}

// EnsureBackupDir creates the backup directory if it does not exist.
func (m *Manager) EnsureBackupDir() error {
	return os.MkdirAll(m.backupDir, 0750)
}

// SaveToFile writes backup bytes to a timestamped file in the backup directory.
func (m *Manager) SaveToFile(data []byte) (string, error) {
	if err := m.EnsureBackupDir(); err != nil {
		return "", err
	}
	filename := fmt.Sprintf("backup-%s.json", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(m.backupDir, filename)
	if err := os.WriteFile(path, data, 0640); err != nil {
		return "", err
	}
	return path, nil
}

// ─── Internal helpers ────────────────────────────────────────────────────────

// upsertJSON iterates a slice of JSON objects and attempts simple row restores
// by converting each row's id column to a UUID and upserting via raw SQL.
// Returns (count, warning string).
func (m *Manager) upsertJSON(ctx context.Context, table string, records []map[string]any, _ string) (int, string) {
	if !allowedRestoreTables[table] {
		slog.Warn("backup restore: テーブルがホワイトリストにありません", "table", table)
		return 0, fmt.Sprintf("テーブル %q はリストアが許可されていません", table)
	}
	n := 0
	for _, row := range records {
		id, ok := row["id"]
		if !ok {
			continue
		}
		rowJSON, err := json.Marshal(row)
		if err != nil {
			continue
		}
		// Use PostgreSQL's jsonb INSERT … ON CONFLICT DO NOTHING pattern.
		// table is validated against allowedRestoreTables above, so interpolation is safe.
		_, err = m.pool.Exec(ctx,
			`INSERT INTO `+table+` SELECT * FROM jsonb_populate_record(null::`+table+`, $1::jsonb) ON CONFLICT (id) DO NOTHING`,
			string(rowJSON),
		)
		if err != nil {
			slog.Debug("backup restore: skipping row", "table", table, "id", id, "error", err)
			continue
		}
		n++
	}
	return n, ""
}
