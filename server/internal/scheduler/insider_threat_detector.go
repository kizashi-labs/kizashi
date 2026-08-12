package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// InsiderThreatDetector detects insider threat patterns by periodically analyzing audit logs.
type InsiderThreatDetector struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewInsiderThreatDetector creates a new InsiderThreatDetector.
func NewInsiderThreatDetector(pool *pgxpool.Pool, nc *nats.Conn) *InsiderThreatDetector {
	return &InsiderThreatDetector{pool: pool, nc: nc}
}

// Run starts the insider threat detection loop.
func (d *InsiderThreatDetector) Run(ctx context.Context) {
	slog.Info("インサイダー脅威検知スケジューラーを開始しました")
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	// Run once immediately
	d.detect(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("インサイダー脅威検知スケジューラーを停止しました")
			return
		case <-ticker.C:
			d.detect(ctx)
		}
	}
}

func (d *InsiderThreatDetector) detect(ctx context.Context) {
	d.detectAfterHoursAccess(ctx)
	d.detectPrivilegeEscalation(ctx)
	d.detectBulkDataAccess(ctx)
	d.detectFailedLoginSpike(ctx)
}

func (d *InsiderThreatDetector) auditTableExists(ctx context.Context) bool {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='audit_logs')`).Scan(&exists)
	return err == nil && exists
}

func (d *InsiderThreatDetector) detectAfterHoursAccess(ctx context.Context) {
	if !d.auditTableExists(ctx) {
		return
	}

	const threshold = 5

	type afterHoursResult struct {
		UserID *string
		Count  int
	}

	rows, err := d.pool.Query(ctx, `
		SELECT user_id::text, COUNT(*) as action_count
		FROM audit_logs
		WHERE created_at >= NOW() - INTERVAL '15 minutes'
		  AND (EXTRACT(HOUR FROM created_at) >= 22 OR EXTRACT(HOUR FROM created_at) < 6)
		GROUP BY user_id
		HAVING COUNT(*) > $1`, threshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var r afterHoursResult
		if err := rows.Scan(&r.UserID, &r.Count); err != nil {
			continue
		}
		var userID *uuid.UUID
		if r.UserID != nil {
			if parsed, err := uuid.Parse(*r.UserID); err == nil {
				userID = &parsed
			}
		}
		description := fmt.Sprintf("深夜時間帯（22:00-06:00）に %d 件のアクセスが検出されました", r.Count)
		d.createAlert(ctx, "時間外アクセス異常検知", description, 3, userID)
	}
}

func (d *InsiderThreatDetector) detectPrivilegeEscalation(ctx context.Context) {
	if !d.auditTableExists(ctx) {
		return
	}

	rows, err := d.pool.Query(ctx, `
		SELECT user_id::text, action, created_at
		FROM audit_logs
		WHERE created_at >= NOW() - INTERVAL '15 minutes'
		  AND (action = 'role_change' OR action = 'permission_grant')
		ORDER BY created_at DESC`)
	if err != nil {
		return
	}
	defer rows.Close()

	type escalationEvent struct {
		UserID    *string
		Action    string
		CreatedAt time.Time
	}

	var events []escalationEvent
	for rows.Next() {
		var e escalationEvent
		if err := rows.Scan(&e.UserID, &e.Action, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	rows.Close()

	for _, e := range events {
		var userID *uuid.UUID
		if e.UserID != nil {
			if parsed, err := uuid.Parse(*e.UserID); err == nil {
				userID = &parsed
			}
		}
		description := fmt.Sprintf("アクション '%s' による権限昇格が検出されました（%s）",
			e.Action, e.CreatedAt.Format(time.RFC3339))
		d.createAlert(ctx, "権限昇格検知", description, 4, userID)
	}
}

func (d *InsiderThreatDetector) detectBulkDataAccess(ctx context.Context) {
	if !d.auditTableExists(ctx) {
		return
	}

	const threshold = 100

	rows, err := d.pool.Query(ctx, `
		SELECT user_id::text, COUNT(*) as action_count
		FROM audit_logs
		WHERE created_at >= NOW() - INTERVAL '15 minutes'
		  AND user_id IS NOT NULL
		GROUP BY user_id
		HAVING COUNT(*) > $1`, threshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var userIDStr string
		var count int
		if err := rows.Scan(&userIDStr, &count); err != nil {
			continue
		}
		var userID *uuid.UUID
		if parsed, err := uuid.Parse(userIDStr); err == nil {
			userID = &parsed
		}
		description := fmt.Sprintf("ユーザーが15分間で %d 件のアクションを実行しました（大量データアクセスパターン）", count)
		d.createAlert(ctx, "大量データアクセス検知", description, 4, userID)
	}
}

func (d *InsiderThreatDetector) detectFailedLoginSpike(ctx context.Context) {
	if !d.auditTableExists(ctx) {
		return
	}

	const threshold = 10

	rows, err := d.pool.Query(ctx, `
		SELECT user_id::text, COUNT(*) as fail_count
		FROM audit_logs
		WHERE created_at >= NOW() - INTERVAL '15 minutes'
		  AND action = 'login_failed'
		  AND user_id IS NOT NULL
		GROUP BY user_id
		HAVING COUNT(*) > $1`, threshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var userIDStr string
		var count int
		if err := rows.Scan(&userIDStr, &count); err != nil {
			continue
		}
		var userID *uuid.UUID
		if parsed, err := uuid.Parse(userIDStr); err == nil {
			userID = &parsed
		}
		description := fmt.Sprintf("同一ユーザーのログイン失敗が15分間で %d 回検出されました", count)
		d.createAlert(ctx, "ログイン失敗急増検知", description, 3, userID)
	}
}

func (d *InsiderThreatDetector) createAlert(ctx context.Context, title, description string, severity int, userID *uuid.UUID) {
	var alertsExist bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alerts')`).Scan(&alertsExist)
	if err != nil || !alertsExist {
		slog.Warn("alertsテーブルが存在しないため、アラートを作成できません", "title", title)
		return
	}

	var alertID string
	err = d.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, description, severity, status, source)
		 VALUES ($1, $2, $3, 'open', 'insider_threat_detector') RETURNING id`,
		title, description, severity,
	).Scan(&alertID)
	if err != nil {
		slog.Error("インサイダー脅威アラートの作成に失敗しました", "error", err, "title", title)
		return
	}

	slog.Info("インサイダー脅威アラートを作成しました", "id", alertID, "title", title)

	// Publish to NATS
	if d.nc != nil {
		payload := []byte(`{"id":"` + alertID + `","title":"` + title + `","severity":` + itoa(severity) + `}`)
		if err := d.nc.Publish("alerts.new", payload); err != nil {
			slog.Warn("NATSへのアラート送信に失敗しました", "error", err)
		}
	}
}
