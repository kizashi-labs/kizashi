package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCExpirySweeper periodically deactivates IOCs whose STIX valid_until
// (ioc_entries.expires_at) has passed. Expiring stale indicators keeps the
// matcher from alerting on intel the source no longer vouches for, without
// deleting the row (history/audit is preserved; a fresh import can re-activate).
type IOCExpirySweeper struct {
	pool     *pgxpool.Pool
	interval time.Duration
}

// NewIOCExpirySweeper creates a sweeper. A non-positive interval defaults to 1h.
func NewIOCExpirySweeper(pool *pgxpool.Pool, interval time.Duration) *IOCExpirySweeper {
	if interval <= 0 {
		interval = time.Hour
	}
	return &IOCExpirySweeper{pool: pool, interval: interval}
}

// Run starts the sweep loop. Designed to be called as a goroutine. It runs once
// on startup to catch indicators that expired while the server was offline.
// sweepOnce は1回分の掃除。sweep の戻り値をここで捌いてあるのは、
// trackRun に渡す形にするためです。
func (s *IOCExpirySweeper) sweepOnce(ctx context.Context) {
	if n, err := s.sweep(ctx); err != nil {
		slog.Debug("IOC失効スイープをスキップ", "error", err)
	} else if n > 0 {
		slog.Info("失効IOCを無効化しました", "count", n)
	}
}

func (s *IOCExpirySweeper) Run(ctx context.Context) {
	slog.Info("IOC失効スイーパー起動", "interval", s.interval)
	trackRun(ctx, "ioc_expiry_sweeper", s.sweepOnce)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "ioc_expiry_sweeper", s.sweepOnce)
		}
	}
}

// sweep deactivates active IOCs whose expires_at is in the past and returns the
// number of rows affected.
func (s *IOCExpirySweeper) sweep(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE ioc_entries
		SET is_active = FALSE, updated_at = NOW()
		WHERE is_active = TRUE
		  AND expires_at IS NOT NULL
		  AND expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
