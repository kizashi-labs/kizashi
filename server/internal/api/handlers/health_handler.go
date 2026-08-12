package handlers

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/edr-platform/server/internal/wsbus"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthHandler provides health, readiness, and liveness endpoints.
type HealthHandler struct {
	pool      *pgxpool.Pool
	startTime time.Time
	version   string
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(pool *pgxpool.Pool, version string) *HealthHandler {
	return &HealthHandler{
		pool:      pool,
		startTime: time.Now(),
		version:   version,
	}
}

// Live handles GET /healthz — liveness probe (is the process alive?)
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "alive",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// Ready handles GET /readyz — readiness probe (can the service handle traffic?)
func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	// Check database
	dbStatus := "ok"
	if err := h.pool.Ping(ctx); err != nil {
		dbStatus = "error: " + err.Error()
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "not_ready",
			"database": dbStatus,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"database": dbStatus,
	})
}

// Status handles GET /api/v1/status — detailed status for monitoring.
func (h *HealthHandler) Status(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	// DB check
	dbOK := true
	dbLatencyMs := int64(0)
	dbStart := time.Now()
	if err := h.pool.Ping(ctx); err != nil {
		dbOK = false
	} else {
		dbLatencyMs = time.Since(dbStart).Milliseconds()
	}

	// DB pool stats
	poolStats := h.pool.Stat()

	// Memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(h.startTime)

	status := "healthy"
	httpStatus := http.StatusOK
	if !dbOK {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, gin.H{
		"status":  status,
		"version": h.version,
		"uptime":  uptime.String(),
		"database": gin.H{
			"ok":            dbOK,
			"latency_ms":    dbLatencyMs,
			"pool_total":    poolStats.TotalConns(),
			"pool_idle":     poolStats.IdleConns(),
			"pool_acquired": poolStats.AcquiredConns(),
		},
		"runtime": gin.H{
			"goroutines":    runtime.NumGoroutine(),
			"heap_alloc_mb": memStats.HeapAlloc / 1024 / 1024,
			"gc_runs":       memStats.NumGC,
		},
		"websocket_clients": wsbus.Global().ConnectedCount(),
	})
}
