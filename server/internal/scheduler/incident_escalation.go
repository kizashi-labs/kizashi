package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentEscalator automatically escalates incidents based on age and severity.
type IncidentEscalator struct {
	pool          *pgxpool.Pool
	checkInterval time.Duration
}

func NewIncidentEscalator(pool *pgxpool.Pool) *IncidentEscalator {
	return &IncidentEscalator{
		pool:          pool,
		checkInterval: 15 * time.Minute,
	}
}

func (e *IncidentEscalator) Run(ctx context.Context) {
	ticker := time.NewTicker(e.checkInterval)
	defer ticker.Stop()
	slog.Info("インシデントエスカレーター起動")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.escalate(ctx)
		}
	}
}

func (e *IncidentEscalator) escalate(ctx context.Context) {
	// Escalate critical incidents not resolved within 1 hour.
	n, err := e.escalateCritical(ctx)
	if err != nil {
		slog.Error("クリティカルエスカレーション失敗", "error", err)
	} else if n > 0 {
		slog.Info("クリティカルインシデントをエスカレーション", "count", n)
	}

	// Escalate high incidents not resolved within 4 hours.
	n, err = e.escalateHigh(ctx)
	if err != nil {
		slog.Error("高重大度エスカレーション失敗", "error", err)
	} else if n > 0 {
		slog.Info("高重大度インシデントをエスカレーション", "count", n)
	}
}

// escalateCritical appends an escalation notice to critical incidents that have
// been open for more than 1 hour without resolution.
// The incidents table uses a numeric severity column (SMALLINT 1-10) and a
// description column (TEXT). There is no "notes" column; description is used
// instead to record the escalation marker.
func (e *IncidentEscalator) escalateCritical(ctx context.Context) (int64, error) {
	result, err := e.pool.Exec(ctx,
		`UPDATE incidents
		 SET description = COALESCE(description,'') || $1,
		     updated_at  = NOW()
		 WHERE severity >= 9
		   AND status NOT IN ('resolved','closed')
		   AND created_at < NOW() - INTERVAL '1 hour'
		   AND (description IS NULL OR description NOT LIKE '%[自動エスカレーション]%')`,
		fmt.Sprintf("\n\n[自動エスカレーション] %s: クリティカルインシデントが1時間以内に解決されていません。",
			time.Now().Format("2006-01-02 15:04:05")),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// escalateHigh appends an escalation notice to high-severity incidents that have
// been open for more than 4 hours without resolution.
func (e *IncidentEscalator) escalateHigh(ctx context.Context) (int64, error) {
	result, err := e.pool.Exec(ctx,
		`UPDATE incidents
		 SET description = COALESCE(description,'') || $1,
		     updated_at  = NOW()
		 WHERE severity BETWEEN 7 AND 8
		   AND status NOT IN ('resolved','closed')
		   AND created_at < NOW() - INTERVAL '4 hours'
		   AND (description IS NULL OR description NOT LIKE '%[自動エスカレーション-高]%')`,
		fmt.Sprintf("\n\n[自動エスカレーション-高] %s: 高重大度インシデントが4時間以内に解決されていません。",
			time.Now().Format("2006-01-02 15:04:05")),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
