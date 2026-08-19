package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/apikeys"
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
			trackRun(ctx, "api_key_rotator", r.rotate)
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
		fail(ctx, err, "APIKeyRotator: api_keysテーブルの存在確認に失敗しました")
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
//
// This used to probe for the disabled_reason column and, when it was missing —
// which it always was, no migration created it — run a second copy of the same
// UPDATE without the reason. Keys were retired correctly and left no record of
// why, which is the one thing an operator needs when a key stops working.
// Migration 378 adds the column; the probe and the duplicate branch are gone.
func (r *APIKeyRotator) disableInactiveKeys(ctx context.Context) {
	type disabledKey struct {
		id     string
		name   string
		userID string
	}
	var disabled []disabledKey

	rows, err := r.pool.Query(ctx,
		`UPDATE api_keys
		 SET enabled = false, disabled_reason = $1
		 WHERE enabled = true
		   AND last_used_at < NOW() - INTERVAL '90 days'
		 RETURNING id::text, COALESCE(name,''), COALESCE(user_id::text,'')`,
		apikeys.DisabledReasonInactive,
	)
	if err != nil {
		fail(ctx, err, "APIKeyRotator: 非アクティブキーの無効化に失敗しました")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k disabledKey
		if scanErr := rows.Scan(&k.id, &k.name, &k.userID); scanErr == nil {
			disabled = append(disabled, k)
		}
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "APIKeyRotator: 無効化結果の読み取りに失敗しました")
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
	// **確認できなかったことを「無い」と答えていました。** `_ =` で
	// 捨てていたので、DB が一時的に応答しないだけで `hasExpiresAt` は
	// false のままになり、期限切れ間近の API キーの通知が丸ごと
	// 飛びます —— しかもログは「カラムが存在しない」です。
	// 隣（同じファイルの api_keys テーブルの確認）は最初からこの形です。
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name   = 'api_keys'
			  AND column_name  = 'expires_at'
		)`,
	).Scan(&hasExpiresAt); err != nil {
		fail(ctx, err, "APIKeyRotator: expires_at列の存在確認に失敗しました")
		return
	}

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
		fail(ctx, err, "APIKeyRotator: 期限切れ予定キーのクエリに失敗しました")
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
				fail(ctx, pubErr, "APIKeyRotator: api_key.expiring_soon NATSパブリッシュに失敗しました")
			}
		}
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "期限切れ予定キーの走査が途中で終わりました。警告が届かないキーがあります")
	}

	if count > 0 {
		slog.Info("APIKeyRotator: 期限切れ予定キーに警告を送信しました", "count", count)
	} else {
		slog.Debug("APIKeyRotator: 30日以内に期限切れになるAPIキーはありません")
	}
}
