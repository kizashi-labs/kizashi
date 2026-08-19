package handlers

import (
	"context"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// hostResources returns host CPU/memory/disk utilisation percentages via
// gopsutil. Each metric is best-effort: a read error simply omits that key so
// the health endpoint never fails on resource collection.
func hostResources(ctx context.Context) map[string]interface{} {
	res := map[string]interface{}{}
	// Short blocking interval gives an accurate instantaneous CPU% on every
	// call (interval 0 would return 0 on the first call).
	if pcts, err := cpu.PercentWithContext(ctx, 150*time.Millisecond, false); err == nil && len(pcts) > 0 {
		res["cpu_percent"] = roundTo2dp(pcts[0])
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		res["memory_percent"] = roundTo2dp(vm.UsedPercent)
	}
	if du, err := disk.UsageWithContext(ctx, "/"); err == nil {
		res["disk_percent"] = roundTo2dp(du.UsedPercent)
	}
	return res
}

var serverStartTime = time.Now()
var requestCounter int64

// DetailedHealthHandler provides comprehensive system health information.
type DetailedHealthHandler struct {
	pool    *pgxpool.Pool
	natsCon *nats.Conn // may be nil
	version string
}

func NewDetailedHealthHandler(pool *pgxpool.Pool, nc *nats.Conn, version string) *DetailedHealthHandler {
	if version == "" {
		version = "1.0.0"
	}
	return &DetailedHealthHandler{pool: pool, natsCon: nc, version: version}
}

// IncrementRequestCounter atomically increments the global request counter.
func IncrementRequestCounter() {
	atomic.AddInt64(&requestCounter, 1)
}

// DetailedHealth handles GET /api/v1/health/detailed
func (h *DetailedHealthHandler) DetailedHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	services := map[string]interface{}{}
	overallOK := true

	// Database check
	dbStart := time.Now()
	dbStatus := "ok"
	var dbMsg string
	if err := h.pool.Ping(ctx); err != nil {
		dbStatus = "error"
		dbMsg = err.Error()
		overallOK = false
	}
	dbLatency := time.Since(dbStart).Milliseconds()
	poolStats := h.pool.Stat()
	services["database"] = map[string]interface{}{
		"status":            dbStatus,
		"message":           dbMsg,
		"latency_ms":        dbLatency,
		"total_connections": poolStats.TotalConns(),
		"idle_connections":  poolStats.IdleConns(),
		"max_connections":   poolStats.MaxConns(),
	}

	// NATS check
	if h.natsCon != nil {
		natsStatus := "ok"
		if !h.natsCon.IsConnected() {
			natsStatus = "disconnected"
			overallOK = false
		}
		services["nats"] = map[string]interface{}{
			"status":    natsStatus,
			"connected": h.natsCon.IsConnected(),
		}
	} else {
		services["nats"] = map[string]interface{}{"status": "not_configured"}
	}

	// Memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memStatus := "ok"
	if memStats.Sys > 1*1024*1024*1024 { // > 1GB
		memStatus = "warning"
	}
	services["memory"] = map[string]interface{}{
		"status":   memStatus,
		"alloc_mb": memStats.Alloc / 1024 / 1024,
		"sys_mb":   memStats.Sys / 1024 / 1024,
		"heap_mb":  memStats.HeapInuse / 1024 / 1024,
		"gc_count": memStats.NumGC,
	}

	// Goroutines
	goroutineCount := runtime.NumGoroutine()
	goroutineStatus := "ok"
	if goroutineCount > 10000 {
		goroutineStatus = "warning"
	}
	services["goroutines"] = map[string]interface{}{
		"status": goroutineStatus,
		"count":  goroutineCount,
	}

	// Business counts (best effort — don't fail health check if queries fail)
	counts := map[string]int{}
	var cntAgents, cntAlerts, cntIncidents int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status='online'`).Scan(&cntAgents)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE status='open'`).Scan(&cntAlerts)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`).Scan(&cntIncidents)) {
		return
	}
	counts["agents_online"] = cntAgents
	counts["open_alerts"] = cntAlerts
	counts["active_incidents"] = cntIncidents

	status := "ok"
	if !overallOK {
		status = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         status,
		"version":        h.version,
		"uptime_seconds": int64(time.Since(serverStartTime).Seconds()),
		"total_requests": atomic.LoadInt64(&requestCounter),
		"timestamp":      time.Now(),
		"services":       services,
		"counts":         counts,
		"resources":      hostResources(ctx),
		"go_version":     runtime.Version(),
		"cpu_count":      runtime.NumCPU(),
	})
}

// GetUptimeStats handles GET /api/v1/health/uptime
//
// Availability is not measured by this platform, and this endpoint says so.
//
// It used to query a uptime_events table behind an existence probe, and when
// the probe failed — which was always, no migration creates that table and no
// code writes it — it returned uptime_30d=99.9, uptime_7d=100.0 and
// downtime_incidents=0. Those figures were invented, not measured, and this
// route is unauthenticated: they were served to anyone who asked, and the
// public /status page rendered them as the product's SLA record.
//
// Reporting nothing is worth less than reporting a real number, and worth far
// more than reporting a comforting one. The fields are kept and set to null so
// existing consumers keep parsing, with measured=false to say plainly why.
// Recording real downtime needs a writer that survives the outages it is
// measuring — a heartbeat whose gaps are the outage — which does not exist
// here; a reader alone cannot conjure the history.
func (h *DetailedHealthHandler) GetUptimeStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"measured":           false,
		"uptime_30d":         nil,
		"uptime_7d":          nil,
		"downtime_incidents": nil,
		"last_incident":      nil,
		"note":               "稼働率は計測されていません。計測基盤が未実装のため、この項目は数値を返しません。",
	})
}

// depResult is a generic dependency status entry.
type depResult struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	LatencyMs *int64   `json:"latency_ms,omitempty"`
	FreeGB    *float64 `json:"free_gb,omitempty"`
	Message   string   `json:"message,omitempty"`
}

// GetDependencies handles GET /api/v1/health/dependencies
// Checks each external dependency and reports status with latency.
func (h *DetailedHealthHandler) GetDependencies(c *gin.Context) {
	var deps []depResult

	// --- PostgreSQL ---
	pgCtx, pgCancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer pgCancel()

	pgStart := time.Now()
	pgStatus := "up"
	var pgMsg string
	var pgRow int
	err := h.pool.QueryRow(pgCtx, `SELECT 1`).Scan(&pgRow)
	if err != nil {
		pgStatus = "down"
		pgMsg = err.Error()
	}
	pgLatency := time.Since(pgStart).Milliseconds()
	pgDep := depResult{Name: "postgresql", Status: pgStatus, LatencyMs: &pgLatency}
	if pgMsg != "" {
		pgDep.Message = pgMsg
	}
	deps = append(deps, pgDep)

	// --- NATS ---
	natsStatus := "up"
	if h.natsCon == nil {
		natsStatus = "not_configured"
	} else if !h.natsCon.IsConnected() {
		natsStatus = "down"
	}
	deps = append(deps, depResult{Name: "nats", Status: natsStatus})

	// --- Disk (platform-specific) ---
	di := checkDisk()
	diskDep := depResult{Name: di.Name, Status: di.Status}
	if di.FreeGB != nil {
		diskDep.FreeGB = di.FreeGB
	}
	if di.Message != "" {
		diskDep.Message = di.Message
	}
	deps = append(deps, diskDep)

	c.JSON(http.StatusOK, gin.H{
		"dependencies": deps,
	})
}

// GetIncidentHistory handles GET /api/v1/health/incidents
//
// Service incidents are not recorded, and this endpoint says so.
//
// It used to read a service_incidents table behind an existence probe that no
// migration satisfies, and returned an empty list when it failed. Paired with
// the fabricated uptime above, an empty list did not read as "not tracked" —
// it read as "no incidents have occurred", which is the same claim made twice.
func (h *DetailedHealthHandler) GetIncidentHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"measured":  false,
		"incidents": []interface{}{},
		"note":      "サービス障害履歴は記録されていません。空のリストは「障害なし」を意味しません。",
	})
}

// DiskInfo holds disk dependency check result; implemented per-platform.
type DiskInfo struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	FreeGB  *float64 `json:"free_gb,omitempty"`
	Message string   `json:"message,omitempty"`
}

// roundTo2dp rounds a float64 to 2 decimal places.
func roundTo2dp(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
