package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// HuntScheduler runs saved hunt queries on schedule and creates alerts on findings.
type HuntScheduler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

func NewHuntScheduler(pool *pgxpool.Pool, nc *nats.Conn) *HuntScheduler {
	return &HuntScheduler{pool: pool, nc: nc}
}

func (s *HuntScheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScheduledHunts(ctx)
		}
	}
}

// savedHuntRow holds a single row from saved_hunt_queries.
type savedHuntRow struct {
	id        string
	name      string
	query     string
	lastRunAt *time.Time
}

func (s *HuntScheduler) runScheduledHunts(ctx context.Context) {
	// 1. Check if saved_hunt_queries table exists.
	var tableExists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'saved_hunt_queries'
		)`,
	).Scan(&tableExists)
	if err != nil {
		slog.Warn("ハントスケジューラー: テーブル存在確認に失敗しました", "error", err)
		return
	}
	if !tableExists {
		slog.Debug("ハントスケジューラー: saved_hunt_queries テーブルが存在しません。スキップします")
		return
	}

	// 2. Check whether the scheduled and last_run_at columns exist.
	var hasScheduled, hasLastRun bool
	colCheckSQL := `
		SELECT
			COUNT(*) FILTER (WHERE column_name = 'scheduled')    > 0,
			COUNT(*) FILTER (WHERE column_name = 'last_run_at')  > 0
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'saved_hunt_queries'
	`
	if err := s.pool.QueryRow(ctx, colCheckSQL).Scan(&hasScheduled, &hasLastRun); err != nil {
		slog.Warn("ハントスケジューラー: カラム確認に失敗しました", "error", err)
		return
	}

	if !hasScheduled || !hasLastRun {
		slog.Debug("ハントスケジューラー: scheduled/last_run_at カラムが存在しません。スキップします",
			"hasScheduled", hasScheduled, "hasLastRun", hasLastRun)
		return
	}

	// 3. Query hunts that are due to run.
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, query, last_run_at
		 FROM saved_hunt_queries
		 WHERE scheduled = true
		   AND (last_run_at IS NULL OR last_run_at < NOW() - INTERVAL '1 hour')
		 LIMIT 10`,
	)
	if err != nil {
		slog.Warn("ハントスケジューラー: クエリ取得に失敗しました", "error", err)
		return
	}
	defer rows.Close()

	var hunts []savedHuntRow
	for rows.Next() {
		var h savedHuntRow
		if err := rows.Scan(&h.id, &h.name, &h.query, &h.lastRunAt); err != nil {
			slog.Warn("ハントスケジューラー: 行のスキャンに失敗しました", "error", err)
			continue
		}
		hunts = append(hunts, h)
	}
	rows.Close()

	if len(hunts) == 0 {
		slog.Debug("ハントスケジューラー: 実行すべきスケジュールハントはありません")
		return
	}

	slog.Info("ハントスケジューラー: スケジュールハントを実行します", "count", len(hunts))

	for _, hunt := range hunts {
		s.executeHunt(ctx, hunt)
	}
}

func (s *HuntScheduler) executeHunt(ctx context.Context, hunt savedHuntRow) {
	// Wrap execution in recover to handle panics from invalid SQL gracefully.
	var resultCount int
	var execErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				execErr = fmt.Errorf("パニック: %v", r)
			}
		}()

		// Validate and execute the hunt query.
		// Only SELECT statements are permitted; anything else is rejected to
		// prevent arbitrary write operations via scheduled hunts.
		if err := validateSelectOnly(hunt.query); err != nil {
			execErr = fmt.Errorf("クエリ検証エラー: %w", err)
			return
		}
		wrappedSQL := `SELECT COUNT(*) FROM (` + hunt.query + `) AS _hunt_results`
		if err := s.pool.QueryRow(ctx, wrappedSQL).Scan(&resultCount); err != nil {
			execErr = err
		}
	}()

	if execErr != nil {
		slog.Warn("ハントスケジューラー: クエリ実行に失敗しました",
			"hunt_id", hunt.id,
			"hunt_name", hunt.name,
			"error", execErr,
		)
		// Still update last_run_at so we don't retry a broken query every cycle.
		s.updateLastRunAt(ctx, hunt.id)
		return
	}

	// 4. Update last_run_at.
	s.updateLastRunAt(ctx, hunt.id)

	slog.Info("ハントスケジューラー: ハント完了",
		"hunt_id", hunt.id,
		"hunt_name", hunt.name,
		"result_count", resultCount,
	)

	// 5. If results found, create an alert and publish to NATS.
	if resultCount > 0 {
		s.createAlert(ctx, hunt, resultCount)
	}
}

func (s *HuntScheduler) updateLastRunAt(ctx context.Context, huntID string) {
	if _, err := s.pool.Exec(ctx,
		`UPDATE saved_hunt_queries SET last_run_at = NOW() WHERE id = $1`,
		huntID,
	); err != nil {
		slog.Warn("ハントスケジューラー: last_run_at の更新に失敗しました",
			"hunt_id", huntID, "error", err)
	}
}

func (s *HuntScheduler) createAlert(ctx context.Context, hunt savedHuntRow, count int) {
	title := fmt.Sprintf("脅威ハント検出: %s (%d件)", hunt.name, count)

	// Insert alert into the alerts table if it exists.
	var alertID string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, severity, status, source, description, created_at, updated_at)
		 VALUES ($1, 7, 'open', 'hunt_scheduler', $2, NOW(), NOW())
		 RETURNING id`,
		title,
		fmt.Sprintf("スケジュールハント '%s' が %d 件の一致を検出しました", hunt.name, count),
	).Scan(&alertID)

	if err != nil {
		slog.Warn("ハントスケジューラー: アラートの作成に失敗しました",
			"hunt_name", hunt.name, "error", err)
		// Publish to NATS even if DB insert fails.
		s.publishNATSAlert(hunt, count, "")
		return
	}

	slog.Info("ハントスケジューラー: アラートを作成しました",
		"alert_id", alertID,
		"hunt_name", hunt.name,
		"count", count,
	)

	s.publishNATSAlert(hunt, count, alertID)
}

func (s *HuntScheduler) publishNATSAlert(hunt savedHuntRow, count int, alertID string) {
	if s.nc == nil {
		return
	}

	payload := map[string]interface{}{
		"source":     "hunt_scheduler",
		"hunt_id":    hunt.id,
		"hunt_name":  hunt.name,
		"count":      count,
		"alert_id":   alertID,
		"title":      fmt.Sprintf("脅威ハント検出: %s (%d件)", hunt.name, count),
		"severity":   7,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("ハントスケジューラー: NATSペイロードのシリアライズに失敗しました", "error", err)
		return
	}

	if err := s.nc.Publish("alerts.new", data); err != nil {
		slog.Warn("ハントスケジューラー: NATS publishに失敗しました",
			"subject", "alerts.new", "error", err)
		return
	}

	slog.Info("ハントスケジューラー: NATS alerts.new を発行しました",
		"hunt_name", hunt.name, "count", count)
}

// validateSelectOnly rejects queries that are not read-only SELECT statements.
// This prevents malicious saved hunts from executing DML/DDL via the scheduler.
func validateSelectOnly(query string) error {
	// Trim leading whitespace and check the first keyword.
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	if !strings.HasPrefix(trimmed, "SELECT") && !strings.HasPrefix(trimmed, "WITH") {
		return fmt.Errorf("ハントクエリはSELECTまたはWITH句で開始する必要があります")
	}
	// Block common DML/DDL keywords anywhere in the query.
	forbidden := []string{"INSERT ", "UPDATE ", "DELETE ", "DROP ", "TRUNCATE ", "ALTER ", "CREATE ", "GRANT ", "REVOKE "}
	for _, kw := range forbidden {
		if strings.Contains(trimmed, kw) {
			return fmt.Errorf("ハントクエリに許可されていないキーワードが含まれています: %s", strings.TrimSpace(kw))
		}
	}
	return nil
}
