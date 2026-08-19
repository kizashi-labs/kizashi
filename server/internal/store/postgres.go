// Package store provides database access for the EDR server.
package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantContextKey is the context key used to propagate tenant_id from the
// HTTP middleware through to pgxpool.PrepareConn, enabling PostgreSQL
// Row-Level Security without modifying individual query handlers.
type TenantContextKey struct{}

// TenantFromContext returns the tenant the current request belongs to, if any.
//
// **テナントの出どころはここ1つです。** RLS も、`alerts.tenant_id` 列の
// DEFAULT も、保管時暗号化の鍵の範囲も、すべてこの値から決まります。
// 別々に決めると、行の tenant_id と暗号化に使った鍵がずれ、
// **書けるが二度と読めない行**ができます。
func TenantFromContext(ctx context.Context) string {
	tid, _ := ctx.Value(TenantContextKey{}).(string)
	return tid
}

// prepareConnForTenant sets app.tenant_id on a freshly acquired connection.
//
// 本番と検査で同じ関数を使うために切り出してあります。写しを持つと、
// 検査が通っても本番が同じ経路を通っているとは限りません。
//
// **設定できなかった接続を「使える」と答えないこと。**
//
// ここが `_, _ =` で `true` を返していました。`app.tenant_id` が空の
// ままの接続は、RLS のエスケープ節（空文字か NULL なら全件）が
// **全テナントを通します**（migration 027 / 324）。つまり
// 「設定に失敗した」と「全権限を持っている」が同じ形でした。
//
// `(false, err)` を返すと pgx はその接続を捨て、**要求はこの error で
// 失敗します**（`(false, nil)` だと黙って別の接続で retry するので、
// 恒久的な失敗のときに「too many failed attempts」まで回ります）。
// **絞り込めない接続を配るより、その要求を失敗させる方が安全です。**
func prepareConnForTenant(ctx context.Context, c *pgx.Conn) (bool, error) {
	if tid := TenantFromContext(ctx); tid != "" {
		if _, err := c.Exec(ctx, "SELECT set_config('app.tenant_id', $1, false)", tid); err != nil {
			return false, fmt.Errorf("テナントを設定できない接続は使えません: %w", err)
		}
	}
	return true, nil
}

// clearConnTenant resets app.tenant_id before the connection goes back to the
// pool.
//
// **消せなかった接続は、プールに戻さず捨てます。** 戻すと、次に
// テナントを持たない呼び出し（起動時の初期化や背景の仕事）がその接続を
// 引いたとき、`prepareConnForTenant` は何もしないので、**前のテナントの
// 値のまま**そのテナントに絞られた結果を読みます。
func clearConnTenant(c *pgx.Conn) bool {
	if _, err := c.Exec(context.Background(), "SELECT set_config('app.tenant_id', '', false)"); err != nil {
		slog.Warn("テナントを消せない接続をプールから捨てます", "error", err)
		return false
	}
	return true
}

// DB wraps a pgx connection pool with helper methods.
type DB struct {
	pool *pgxpool.Pool
}

// Connect establishes a connection pool to PostgreSQL/TimescaleDB.
func Connect(ctx context.Context, databaseURL string) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	config.MaxConns = 30
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	// Attach OTEL query tracer so every SQL statement gets a child span.
	// When no OTEL exporter is configured this is effectively a no-op.
	config.ConnConfig.Tracer = telemetry.NewPgxTracer()

	// PrepareConn: if the request context carries a tenant_id (placed there by
	// tenantMiddleware), set app.tenant_id on the connection so PostgreSQL RLS
	// policies automatically filter rows for the correct tenant. Runs before
	// every acquire (same hook point as the deprecated BeforeAcquire).
	//
	// The 3rd set_config arg MUST be false (session-scoped). With true
	// (transaction-scoped) the setting is discarded at the end of THIS Exec's
	// implicit transaction and is therefore NOT visible to the request's
	// subsequent queries — leaving app.tenant_id empty, which the RLS policies'
	// "app.tenant_id IS NULL OR ''" escape clause treats as full cross-tenant
	// access. AfterRelease clears the session value before the connection is
	// reused, so it cannot bleed to the next tenant.
	config.PrepareConn = prepareConnForTenant

	// AfterRelease: reset app.tenant_id so the connection is clean for the next
	// request (prevents tenant bleed-through in the pool). Must also be session-
	// scoped (false) to actually clear the session value PrepareConn set.
	config.AfterRelease = clearConnTenant

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

// Pool returns the underlying pgx pool for direct use in stores.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}
