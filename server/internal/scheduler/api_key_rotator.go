package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// APIKeyRotator disables API keys that haven't been used in 90 days
// and sends warning notifications for keys expiring in 30 days.
type APIKeyRotator struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewAPIKeyRotator creates a new APIKeyRotator.
func NewAPIKeyRotator(pool *pgxpool.Pool, nc *nats.Conn) *APIKeyRotator {
	return &APIKeyRotator{pool: pool, nc: nc}
}

// Run starts the rotator on a 24-hour tick. Designed to be called as a goroutine.
func (r *APIKeyRotator) Run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.rotate(ctx)
		}
	}
}

// rotate performs a single rotation pass: disables inactive keys and warns about expiring keys.
func (r *APIKeyRotator) rotate(ctx context.Context) {
	// 1. Check if api_keys table exists.
	var tableExists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'api_keys'
		)`,
	).Scan(&tableExists)
	if err != nil {
		slog.Warn("APIKeyRotator: api_keysテーブルの存在確認に失敗しました", "error", err)
		return
	}
	if !tableExists {
		slog.Debug("APIKeyRotator: api_keysテーブルが存在しないためスキップします")
		return
	}

	// 2. Disable keys inactive for 90 days.
	r.disableInactiveKeys(ctx)

	// 3. Warn about keys expiring within 30 days.
	r.warnExpiringKeys(ctx)
}

// disableInactiveKeys sets enabled=false for keys unused for 90+ days.
func (r *APIKeyRotator) disableInactiveKeys(ctx context.Context) {
	// Check if disabled_reason column exists.
	var hasDisabledReason bool
	_ = r.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name   = 'api_keys'
			  AND column_name  = 'disabled_reason'
		)`,
	).Scan(&hasDisabledReason)

	type disabledKey struct {
		id     string
		name   string
		userID string
	}
	var disabled []disabledKey

	if hasDisabledReason {
		rows, err := r.pool.Query(ctx,
			`UPDATE api_keys
			 SET enabled = false, disabled_reason = 'inactive_90_days'
			 WHERE enabled = true
			   AND last_used_at < NOW() - INTERVAL '90 days'
			 RETURNING id::text, COALESCE(name,''), COALESCE(user_id::text,'')`,
		)
		if err != nil {
			slog.Warn("APIKeyRotator: 非アクティブキーの無効化に失敗しました", "error", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var k disabledKey
			if scanErr := rows.Scan(&k.id, &k.name, &k.userID); scanErr == nil {
				disabled = append(disabled, k)
			}
		}
	} else {
		rows, err := r.pool.Query(ctx,
			`UPDATE api_keys
			 SET enabled = false
			 WHERE enabled = true
			   AND last_used_at < NOW() - INTERVAL '90 days'
			 RETURNING id::text, COALESCE(name,''), COALESCE(user_id::text,'')`,
		)
		if err != nil {
			slog.Warn("APIKeyRotator: 非アクティブキーの無効化に失敗しました", "error", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var k disabledKey
			if scanErr := rows.Scan(&k.id, &k.name, &k.userID); scanErr == nil {
				disabled = append(disabled, k)
			}
		}
	}

	if len(disabled) > 0 {
		slog.Info("APIKeyRotator: 非アクティブAPIキーを無効化しました", "count", len(disabled))
		for _, k := range disabled {
			slog.Info("APIKeyRotator: キー無効化",
				"key_id", k.id,
				"name", k.name,
				"user_id", k.userID,
			)
		}
	} else {
		slog.Debug("APIKeyRotator: 無効化対象の非アクティブキーはありません")
	}
}

// warnExpiringKeys publishes NATS notifications for keys expiring within 30 days.
func (r *APIKeyRotator) warnExpiringKeys(ctx context.Context) {
	// Check if expires_at column exists.
	var hasExpiresAt bool
	_ = r.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name   = 'api_keys'
			  AND column_name  = 'expires_at'
		)`,
	).Scan(&hasExpiresAt)

	if !hasExpiresAt {
		slog.Debug("APIKeyRotator: expires_atカラムが存在しないため期限チェックをスキップします")
		return
	}

	rows, err := r.pool.Query(ctx,
		`SELECT id::text, COALESCE(name,''), COALESCE(user_id::text,''), expires_at
		 FROM api_keys
		 WHERE enabled = true
		   AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days'`,
	)
	if err != nil {
		slog.Warn("APIKeyRotator: 期限切れ予定キーのクエリに失敗しました", "error", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			id        string
			name      string
			userID    string
			expiresAt time.Time
		)
		if scanErr := rows.Scan(&id, &name, &userID, &expiresAt); scanErr != nil {
			continue
		}
		count++

		daysLeft := int(time.Until(expiresAt).Hours() / 24)
		slog.Info("APIKeyRotator: APIキーが30日以内に期限切れになります",
			"key_id", id,
			"name", name,
			"user_id", userID,
			"expires_at", expiresAt.Format(time.RFC3339),
			"days_left", daysLeft,
		)

		if r.nc != nil {
			payload, _ := json.Marshal(map[string]any{
				"key_id":     id,
				"name":       name,
				"user_id":    userID,
				"expires_at": expiresAt.Format(time.RFC3339),
				"days_left":  daysLeft,
			})
			if pubErr := r.nc.Publish("api_key.expiring_soon", payload); pubErr != nil {
				slog.Warn("APIKeyRotator: api_key.expiring_soon NATSパブリッシュに失敗しました", "error", pubErr)
			}
		}
	}

	if count > 0 {
		slog.Info("APIKeyRotator: 期限切れ予定キーに警告を送信しました", "count", count)
	} else {
		slog.Debug("APIKeyRotator: 30日以内に期限切れになるAPIキーはありません")
	}
}
