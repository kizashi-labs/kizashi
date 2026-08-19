package handlers

import (
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/edr-platform/server/internal/cache"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// SystemHandler exposes system status and performance endpoints.
type SystemHandler struct {
	pool    *pgxpool.Pool
	cache   *cache.Cache
	natsCon *nats.Conn // may be nil
}

// NewSystemHandler creates a SystemHandler.
func NewSystemHandler(pool *pgxpool.Pool, c *cache.Cache, nc *nats.Conn) *SystemHandler {
	return &SystemHandler{pool: pool, cache: c, natsCon: nc}
}

// Status handles GET /api/v1/admin/system/status
func (h *SystemHandler) Status(c *gin.Context) {
	ctx := c.Request.Context()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// serverStartTime is shared with the detailed health handler (same package)
	// so uptime is consistent across both endpoints.
	uptimeSeconds := int64(time.Since(serverStartTime).Seconds())

	resp := gin.H{
		"goroutines":     runtime.NumGoroutine(),
		"memory_mb":      float64(mem.Alloc) / 1024 / 1024,
		"uptime":         time.Since(serverStartTime).String(),
		"uptime_seconds": uptimeSeconds,
	}

	// Host CPU/memory/disk utilisation (%), best-effort — adds cpu_percent etc.
	for k, v := range hostResources(ctx) {
		resp[k] = v
	}

	if h.cache != nil {
		resp["cache_stats"] = h.cache.Stats()
	}

	now := time.Now().Format(time.RFC3339)
	services := make([]gin.H, 0, 3)

	// API Server — this process.
	services = append(services, gin.H{
		"name":           "API Server",
		"status":         "healthy",
		"uptime_seconds": uptimeSeconds,
		"latency_ms":     0,
		"last_check":     now,
	})

	// Database — ping for live status + latency, and expose pool stats.
	if h.pool != nil {
		dbStart := time.Now()
		dbStatus := "healthy"
		if err := h.pool.Ping(ctx); err != nil {
			dbStatus = "down"
		}
		// Microsecond-resolution: a local DB ping is sub-millisecond, so
		// Milliseconds() would round to 0. Report fractional ms instead.
		dbLatency := roundTo2dp(float64(time.Since(dbStart).Microseconds()) / 1000.0)

		s := h.pool.Stat()
		resp["db_pool_stats"] = gin.H{
			"total_conns":    s.TotalConns(),
			"idle_conns":     s.IdleConns(),
			"acquired_conns": s.AcquiredConns(),
			"max_conns":      s.MaxConns(),
		}
		services = append(services, gin.H{
			"name":           "Database",
			"status":         dbStatus,
			"uptime_seconds": uptimeSeconds,
			"latency_ms":     dbLatency,
			"last_check":     now,
		})
	}

	// NATS — connection liveness.
	if h.natsCon != nil {
		natsStatus := "healthy"
		if !h.natsCon.IsConnected() {
			natsStatus = "down"
		}
		services = append(services, gin.H{
			"name":           "NATS",
			"status":         natsStatus,
			"uptime_seconds": uptimeSeconds,
			"latency_ms":     0,
			"last_check":     now,
		})
	} else {
		services = append(services, gin.H{
			"name":           "NATS",
			"status":         "degraded",
			"uptime_seconds": 0,
			"latency_ms":     0,
			"last_check":     now,
		})
	}

	resp["services"] = services

	c.JSON(http.StatusOK, resp)
}

// DBStats handles GET /api/v1/admin/system/db-stats
func (h *SystemHandler) DBStats(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースプールが利用できません"})
		return
	}
	ctx := c.Request.Context()

	// Table sizes from pg_stat_user_tables
	type tableSize struct {
		TableName  string `json:"table_name"`
		RowCount   int64  `json:"row_count"`
		TotalBytes int64  `json:"total_bytes"`
		IndexBytes int64  `json:"index_bytes"`
		SeqScans   int64  `json:"seq_scans"`
		IdxScans   int64  `json:"idx_scans"`
	}
	var tableSizes []tableSize
	// Use relid (the table OID) rather than quote_ident(relname): under
	// TimescaleDB the same relname (e.g. "chunk") exists in multiple schemas,
	// so quote_ident(relname) resolves ambiguously/out of search_path and the
	// whole query errors — leaving table_sizes null. relid is unambiguous.
	rows, err := h.pool.Query(ctx, `
		SELECT relname,
		       n_live_tup,
		       pg_total_relation_size(relid),
		       pg_indexes_size(relid),
		       COALESCE(seq_scan, 0),
		       COALESCE(idx_scan, 0)
		FROM pg_stat_user_tables
		ORDER BY pg_total_relation_size(relid) DESC
		LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ts tableSize
			if rows.Scan(&ts.TableName, &ts.RowCount, &ts.TotalBytes, &ts.IndexBytes, &ts.SeqScans, &ts.IdxScans) == nil {
				tableSizes = append(tableSizes, ts)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Index usage from pg_stat_user_indexes
	type indexUsage struct {
		IndexName  string `json:"index_name"`
		TableName  string `json:"table_name"`
		IndexScans int64  `json:"index_scans"`
	}
	var indexUsages []indexUsage
	idxRows, err := h.pool.Query(ctx, `
		SELECT indexrelname, relname, idx_scan
		FROM pg_stat_user_indexes
		ORDER BY idx_scan DESC
		LIMIT 30`)
	if err == nil {
		defer idxRows.Close()
		for idxRows.Next() {
			var iu indexUsage
			if idxRows.Scan(&iu.IndexName, &iu.TableName, &iu.IndexScans) == nil {
				indexUsages = append(indexUsages, iu)
			}
		}
		if err := idxRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Slow queries (pg_stat_statements if available)
	type slowQuery struct {
		Query   string  `json:"query"`
		Calls   int64   `json:"calls"`
		MeanMs  float64 `json:"mean_ms"`
		TotalMs float64 `json:"total_ms"`
	}
	var slowQueries []slowQuery
	sqRows, err := h.pool.Query(ctx, `
		SELECT LEFT(query,200), calls, mean_exec_time, total_exec_time
		FROM pg_stat_statements
		ORDER BY mean_exec_time DESC
		LIMIT 10`)
	if err == nil {
		defer sqRows.Close()
		for sqRows.Next() {
			var sq slowQuery
			if sqRows.Scan(&sq.Query, &sq.Calls, &sq.MeanMs, &sq.TotalMs) == nil {
				slowQueries = append(slowQueries, sq)
			}
		}
		if err := sqRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Connection count
	var connectionCount int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM pg_stat_activity`,
	).Scan(&connectionCount)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"table_sizes":      tableSizes,
		"index_usage":      indexUsages,
		"slow_queries":     slowQueries,
		"connection_count": connectionCount,
	})
}

// FlushCache handles POST /api/v1/admin/system/cache/flush
func (h *SystemHandler) FlushCache(c *gin.Context) {
	if h.cache != nil {
		h.cache.Flush()
	}
	c.JSON(http.StatusOK, gin.H{"flushed": true})
}
